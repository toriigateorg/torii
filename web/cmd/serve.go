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

	"torii/internal/api"
	"torii/internal/audit"
	"torii/internal/auth"
	"torii/internal/config"
	"torii/internal/db"
	"torii/internal/proxy"
	"torii/internal/web"
)

func Serve() *cli.Command {
	return &cli.Command{
		Name:  "serve",
		Usage: "run the torii server (dev: via air with embedded Nuxt)",
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
	if cfg != nil {
		configureIPExtractor(e, cfg.TrustedProxyCIDRs)
	}
	e.Use(middleware.RequestLogger())
	e.Use(middleware.BodyLimit(1 << 20))
	e.Use(securityHeaders(cfg))

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
		toriiURL := ""
		if cfg != nil {
			toriiURL = cfg.ToriiURL
		}
		spaHandler = web.Handler(toriiURL)
	} else {
		spaHandler = proxy.Nuxt()
		go waitForNuxt("127.0.0.1:3000", 10*time.Second)
	}

	e.Any("/*", dispatch(cfg, cache, auditor, refresher, spaHandler))

	srv := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", host, port),
		Handler:           e,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
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

// hasSessionMarker reports whether the request carries the non-secret session
// marker cookie. The refresh cookie now lives at Path=/_torii/api/v1/, so it
// no longer rides along on service-path requests; the marker (Path=/) is the
// only signal dispatch has that a refresh might succeed on a proxied host.
func hasSessionMarker(r *http.Request) bool {
	ck, err := r.Cookie(auth.SessionCookie)
	return err == nil && ck != nil && ck.Value != ""
}

// isDocumentRequest is true for top-level browser navigations. Dispatch uses
// it to decide between a 302 (safe for navigations) and a JSON 401 (correct
// for XHR/asset callers that would choke on an HTML redirect).
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

// dispatch routes traffic by path: anything under /_torii/* is torii (SPA or
// API, on any host); other paths on TORII_URL bounce to /_torii/, and on a
// matched service host they reverse-proxy to the upstream when authenticated.
func dispatch(cfg *config.Config, cache *proxy.ServiceCache, auditor *audit.Logger, refresher api.SessionRefresher, spa echo.HandlerFunc) echo.HandlerFunc {
	_ = refresher
	return func(c *echo.Context) error {
		path := c.Request().URL.Path
		// Unmatched API paths must not fall through to the SPA — a JSON
		// client expecting an error would parse the index.html as garbage.
		if strings.HasPrefix(path, "/_torii/api/") {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "not found"})
		}
		if path == "/_torii" || strings.HasPrefix(path, "/_torii/") {
			return spa(c)
		}
		if cfg == nil {
			return c.Redirect(http.StatusFound, "/_torii/")
		}
		host := c.Request().Host
		if cfg.IsToriiHost(host) {
			return c.Redirect(http.StatusFound, "/_torii/")
		}
		if cache != nil {
			if svc, ok := cache.Lookup(c.Request().Context(), host); ok {
				claims, err := auth.ClaimsFromProxyRequest(c, cfg.JWTSecret)
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
								"path":   path,
							},
						})
					}
					if !isDocumentRequest(c.Request()) {
						return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
					}
					to := c.Request().URL.RequestURI()
					if hasSessionMarker(c.Request()) {
						return c.Redirect(http.StatusFound, "/_torii/api/v1/refresh_and_redirect?to="+url.QueryEscape(to))
					}
					return c.Redirect(http.StatusFound, "/_torii/signin?to="+url.QueryEscape(to))
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
								"path":   path,
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
				return proxy.ProxyTo(svc, proxy.Identity{
					UserID:   claims.Subject,
					Username: claims.Username,
					Email:    claims.Email,
					Roles:    claims.RoleIDs,
				}, c)
			}
		}
		// Unknown host, non-/_torii path: redirect navigations to /_torii/signin
		// (so the user lands somewhere sensible); 404 everything else. Preserve
		// the original path as ?to= so the SPA can bounce the user back after
		// signin — useful when a service is being provisioned and the cache
		// hasn't picked it up yet.
		if isDocumentRequest(c.Request()) {
			return c.Redirect(http.StatusFound, "/_torii/signin?to="+url.QueryEscape(c.Request().URL.RequestURI()))
		}
		return c.JSON(http.StatusNotFound, map[string]string{"error": "not found"})
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
