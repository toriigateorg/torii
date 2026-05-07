package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	"github.com/urfave/cli/v3"

	"sanmon/internal/api"
	"sanmon/internal/audit"
	"sanmon/internal/auth"
	"sanmon/internal/config"
	"sanmon/internal/db"
	"sanmon/internal/proxy"
	"sanmon/internal/web"
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
				Name:  "migrate",
				Usage: "apply pending migrations before serving",
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
			isInner := c.Bool("inner")

			// Migrations only run on the user-invoked entrypoint (not on each
			// air-spawned restart, which would double-apply).
			if !isInner && c.Bool("migrate") {
				fmt.Println("[migrate] applying pending migrations...")
				if err := migrateUp(""); err != nil {
					return fmt.Errorf("migrate: %w", err)
				}
			}

			if isInner {
				return runInner(ctx, host, int(port))
			}
			// In production, skip air + Nuxt orchestration entirely; the
			// binary serves the embedded SPA directly.
			if isProdEnv() {
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

// runInner is the actual server. In dev it spawns Nuxt as a child and
// reverse-proxies non-/api/* traffic to it; in prod it serves the embedded
// SPA directly.
func runInner(ctx context.Context, host string, port int) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	prod := isProdEnv()

	var nuxtDone <-chan struct{}
	if !prod {
		nuxtDone = startNuxt(ctx)
	}

	pool, err := db.Open(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[db] pool unavailable:", err)
	} else {
		defer pool.Close()
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "[config] auth disabled:", err)
	}

	e := echo.New()
	e.Use(middleware.RequestLogger())

	var cache *proxy.ServiceCache
	if pool != nil {
		cache = proxy.NewServiceCache(db.New(pool), 30*time.Second)
	}

	var auditor *audit.Logger
	if pool != nil && cfg != nil {
		a, err := audit.New(db.New(pool), cfg.AuditLogDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "[audit] disabled:", err)
		} else {
			auditor = a
			defer auditor.Close()
		}
	}

	refresher := api.Register(e, pool, cfg, cache, auditor)

	var spaHandler echo.HandlerFunc
	if prod {
		if !web.HasAssets() {
			fmt.Fprintln(os.Stderr, "[web] WARNING: embedded SPA is empty — build the client (bun run generate) and copy client/.output/public/* into internal/web/dist/ before `go build`")
		}
		spaHandler = web.Handler()
	} else {
		spaHandler = proxy.Nuxt()
		go waitForNuxt("127.0.0.1:3000", 10*time.Second)
	}

	e.Any("/*", dispatch(cfg, cache, auditor, refresher, spaHandler))

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
		if nuxtDone != nil {
			<-nuxtDone
		}
		return err
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = srv.Shutdown(shutdownCtx)

	cancel()
	if nuxtDone != nil {
		<-nuxtDone
	}
	return nil
}

func isProdEnv() bool {
	env := os.Getenv("APP_ENV")
	return env != "" && env != "dev"
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

// dispatch routes incoming non-API traffic by Host. Requests for the sanmon
// domain are served by the SPA handler; requests whose Host matches a
// configured service.domain are reverse-proxied (when the caller carries a
// valid sanmon access token); everything else falls through to the SPA so the
// signin page or 4xx page can render under the unknown domain.
// hasSessionMarker reports whether the request carries the non-secret
// session marker cookie. Used by dispatch to decide whether an unauthenticated
// request on a service domain is worth a refresh-and-redirect attempt
// (marker present → refresh token is still alive) or whether the user is
// genuinely logged out and should fall through to the SPA (no marker →
// avoid loops where /signin keeps redirecting to a refresh that always
// fails).
func hasSessionMarker(r *http.Request) bool {
	ck, err := r.Cookie(auth.SessionCookie)
	return err == nil && ck != nil && ck.Value != ""
}

// isDocumentRequest is true for top-level browser navigations (GET requests
// for HTML). Used to decide whether dispatch should 302-bounce through the
// refresh endpoint or just fall through to the SPA: redirecting an XHR or an
// asset fetch to an HTML response would corrupt those callers.
func isDocumentRequest(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if r.Header.Get("X-Requested-With") != "" {
		return false
	}
	if dest := r.Header.Get("Sec-Fetch-Dest"); dest != "" {
		return dest == "document" || dest == "iframe"
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

func dispatch(cfg *config.Config, cache *proxy.ServiceCache, auditor *audit.Logger, refresher api.SessionRefresher, spa echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		// Never let the SPA handler answer a request that was meant for the
		// API but didn't match a registered route — that would return an
		// HTML body to a JSON client and cause subtle bugs.
		if strings.HasPrefix(c.Request().URL.Path, "/api/") {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "not found"})
		}
		if cfg == nil {
			return spa(c)
		}
		host := c.Request().Host
		if host == cfg.SanmonURL {
			return spa(c)
		}
		if cache != nil {
			if svc, ok := cache.Lookup(c.Request().Context(), host); ok {
				claims, err := auth.ClaimsFromRequest(c, cfg.JWTSecret)
				// Access token expired on a proxied domain. The refresh
				// cookie is path-scoped to /api/v1/ so it isn't sent on
				// a request to "/" — we can't rotate inline. For top-
				// level document navigations we 302 the browser through
				// /api/v1/refresh_and_redirect (where the cookie does
				// ride along) and bounce back. Only do this when an
				// access cookie is actually present: an absent cookie
				// means the user is logged out, so falling through to
				// the SPA is correct (avoids a redirect loop after
				// logout, since the refresh handler would also fail).
				if err != nil && refresher != nil && isDocumentRequest(c.Request()) && hasSessionMarker(c.Request()) {
					to := c.Request().URL.RequestURI()
					return c.Redirect(http.StatusFound, "/api/v1/refresh_and_redirect?to="+url.QueryEscape(to))
				}
				if err != nil {
					if auditor != nil {
						svcID := svc.ID
						auditor.LogFromEcho(c, audit.Event{
							EventType:  audit.EventProxyDenied,
							TargetType: audit.TargetService,
							TargetID:   &svcID,
							TargetName: svc.Title,
							Metadata: map[string]any{
								"reason": "unauthenticated",
								"host":   host,
								"path":   c.Request().URL.Path,
							},
						})
					}
					return spa(c)
				}
				roleIDs := make([]uuid.UUID, 0, len(claims.RoleIDs))
				for _, s := range claims.RoleIDs {
					if id, err := uuid.Parse(s); err == nil {
						roleIDs = append(roleIDs, id)
					}
				}
				if !svc.AllowsAnyRole(roleIDs) {
					if auditor != nil {
						svcID := svc.ID
						var actorID *uuid.UUID
						if id, perr := uuid.Parse(claims.Subject); perr == nil {
							actorID = &id
						}
						auditor.LogFromEcho(c, audit.Event{
							EventType:     audit.EventProxyDenied,
							ActorUserID:   actorID,
							ActorUsername: claims.Username,
							TargetType:    audit.TargetService,
							TargetID:      &svcID,
							TargetName:    svc.Title,
							Metadata: map[string]any{
								"reason": "no_role",
								"host":   host,
								"path":   c.Request().URL.Path,
							},
						})
					}
					return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden: no role grants access to this service"})
				}
				if auditor != nil {
					if uid, perr := uuid.Parse(claims.Subject); perr == nil {
						auditor.LogProxyAccess(c, uid, claims.Username, svc.ID, svc.Title)
					}
				}
				return proxy.ProxyTo(svc, c)
			}
		}
		return spa(c)
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
