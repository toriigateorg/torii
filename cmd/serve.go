package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	"github.com/urfave/cli/v3"

	"sanmon/internal/api"
	"sanmon/internal/db"
	"sanmon/internal/proxy"
)

func Serve() *cli.Command {
	return &cli.Command{
		Name:  "serve",
		Usage: "run the sanmon server (dev: via air with embedded Nuxt)",
		Flags: []cli.Flag{
			&cli.IntFlag{
				Name:    "api-port",
				Value:   1356,
				Usage:   "port for the API server",
				Sources: cli.EnvVars("API_PORT"),
			},
			&cli.StringFlag{
				Name:    "api-host",
				Value:   "0.0.0.0",
				Usage:   "host for the API server",
				Sources: cli.EnvVars("API_HOST"),
			},
			&cli.BoolFlag{
				Name:   "inner",
				Usage:  "internal: invoked by air to actually serve",
				Hidden: true,
			},
		},
		Action: func(ctx context.Context, c *cli.Command) error {
			host := c.String("api-host")
			port := c.Int("api-port")

			if c.Bool("inner") {
				return runInner(ctx, host, int(port))
			}
			return runOuter(ctx, host, int(port))
		},
	}
}

// runOuter execs `air`, propagating host/port via env so the inner invocation
// (./tmp/main serve --inner) picks them up. We do not double-spawn nuxt here:
// the inner binary owns Nuxt as a child per the chosen orchestration model.
func runOuter(ctx context.Context, host string, port int) error {
	air, err := exec.LookPath("air")
	if err != nil {
		return fmt.Errorf("air not found in PATH: %w", err)
	}

	cmd := exec.CommandContext(ctx, air)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Env = append(os.Environ(),
		"API_HOST="+host,
		"API_PORT="+strconv.Itoa(port),
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting air: %w", err)
	}

	go func() {
		<-sigCh
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		}
	}()

	if err := cmd.Wait(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return cli.Exit("", exitErr.ExitCode())
		}
		return err
	}
	return nil
}

// runInner is the actual server: spawns Nuxt as a child, starts echo, and
// reverse-proxies non-/api/* traffic to Nuxt on :3000.
func runInner(ctx context.Context, host string, port int) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	nuxtDone := startNuxt(ctx)

	pool, err := db.Open(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[db] pool unavailable:", err)
	} else {
		defer pool.Close()
	}

	e := echo.New()
	e.Use(middleware.RequestLogger())

	api.Register(e, pool)

	// Catch-all proxy to Nuxt for anything that didn't match /api/v1/*.
	e.Any("/*", proxy.Nuxt())

	go waitForNuxt("127.0.0.1:3000", 10*time.Second)

	srv := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", host, port),
		Handler: e,
	}

	serverErr := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
		close(serverErr)
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	select {
	case <-sigCh:
	case <-ctx.Done():
	case err := <-serverErr:
		cancel()
		<-nuxtDone
		return err
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = srv.Shutdown(shutdownCtx)

	cancel()
	<-nuxtDone
	return nil
}

// startNuxt runs `bun run dev` in ./client. It places the child in its own
// process group so we can SIGTERM the whole tree (bun -> node) on shutdown,
// otherwise port 3000 stays bound after we exit.
func startNuxt(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})

	bun, err := exec.LookPath("bun")
	if err != nil {
		fmt.Fprintln(os.Stderr, "[nuxt] bun not found in PATH:", err)
		close(done)
		return done
	}

	cmd := exec.Command(bun, "run", "dev")
	cmd.Dir = "client"
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "[nuxt] failed to start:", err)
		close(done)
		return done
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go pipePrefixed(&wg, stdout, "[nuxt] ")
	go pipePrefixed(&wg, stderr, "[nuxt] ")

	go func() {
		<-ctx.Done()
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		}
	}()

	go func() {
		defer close(done)
		_ = cmd.Wait()
		wg.Wait()
	}()

	return done
}

func pipePrefixed(wg *sync.WaitGroup, r io.Reader, prefix string) {
	defer wg.Done()
	buf := make([]byte, 4096)
	var carry []byte
	for {
		n, err := r.Read(buf)
		if n > 0 {
			data := append(carry, buf[:n]...)
			start := 0
			for i := 0; i < len(data); i++ {
				if data[i] == '\n' {
					os.Stdout.Write([]byte(prefix))
					os.Stdout.Write(data[start : i+1])
					start = i + 1
				}
			}
			carry = append(carry[:0], data[start:]...)
		}
		if err != nil {
			if len(carry) > 0 {
				os.Stdout.Write([]byte(prefix))
				os.Stdout.Write(carry)
				os.Stdout.Write([]byte("\n"))
			}
			return
		}
	}
}

func waitForNuxt(addr string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 250*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			fmt.Fprintln(os.Stdout, "[nuxt] up on", addr)
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	fmt.Fprintln(os.Stderr, "[nuxt] not ready after", timeout, "- proxy may 502 until it boots")
}
