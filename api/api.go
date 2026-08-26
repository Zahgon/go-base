// Package api configures an http server for administration and application resources.
package api

import (
	"context"
	"net/http"
	"os"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dhax/go-base/api/admin"
	"github.com/dhax/go-base/api/app"
	"github.com/dhax/go-base/auth/authorize"
	"github.com/dhax/go-base/auth/jwt"
	"github.com/dhax/go-base/auth/pwdless"
	"github.com/dhax/go-base/database"
	"github.com/dhax/go-base/email"
	"github.com/dhax/go-base/logging"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// mountedPrefixes are the path prefixes served by a sub router. Requests below one of
// them that match no route are answered by the sub router's not found handler.
var mountedPrefixes = []string{"/auth", "/admin", "/api"}

// protectedPrefixes are the path prefixes guarded by the JWT authenticator.
var protectedPrefixes = []string{"/admin", "/api"}

// adminPrefixes are the path prefixes guarded by the admin role. The sub router applies the
// guard to every request it receives, so it answers before a not found or method not allowed.
var adminPrefixes = []string{"/admin"}

// New configures application resources and routes.
func New(enableCORS bool) (*gin.Engine, error) {
	logger := logging.NewLogger()

	db, err := database.DBConn()
	if err != nil {
		logger.WithField("module", "database").Error(err)
		return nil, err
	}

	mailer, err := email.NewMailer()
	if err != nil {
		logger.WithField("module", "email").Error(err)
		return nil, err
	}

	authStore := database.NewAuthStore(db)
	authResource, err := pwdless.NewResource(authStore, mailer)
	if err != nil {
		logger.WithField("module", "auth").Error(err)
		return nil, err
	}

	adminAPI, err := admin.NewAPI(db)
	if err != nil {
		logger.WithField("module", "admin").Error(err)
		return nil, err
	}

	appAPI, err := app.NewAPI(db)
	if err != nil {
		logger.WithField("module", "app").Error(err)
		return nil, err
	}

	return newRouter(enableCORS, logger, authResource, adminAPI, appAPI), nil
}

// newRouter assembles the router from already configured resources. It is kept separate from
// New so the routing behaviour can be exercised without a database connection.
func newRouter(enableCORS bool, logger *logrus.Logger, authResource *pwdless.Resource, adminAPI *admin.API, appAPI *app.API) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)

	r := gin.New()
	r.RedirectTrailingSlash = false
	r.RedirectFixedPath = false
	r.HandleMethodNotAllowed = false

	r.Use(gin.Recovery())
	r.Use(logging.RequestID())
	// r.Use(logging.RealIP())
	r.Use(timeout(15 * time.Second))

	r.Use(logging.NewStructuredLogger(logger))

	// use CORS middleware if client is not served by this api, e.g. from other domain or CDN
	if enableCORS {
		r.Use(corsConfig())
	}

	authResource.Router(r.Group("/auth"))

	protected := r.Group("")
	protected.Use(authResource.TokenAuth.Verifier())
	protected.Use(jwt.Authenticator)
	adminAPI.Router(protected.Group("/admin"))
	appAPI.Router(protected.Group("/api"))

	r.GET("/healthz", func(c *gin.Context) {
		c.Writer.Write([]byte("ok"))
	})

	spa := SPAHandler("public")
	patterns := routePatterns(r)
	r.NoRoute(
		onlyBelow(protectedPrefixes, authResource.TokenAuth.Verifier()),
		onlyBelow(protectedPrefixes, jwt.Authenticator),
		onlyBelow(adminPrefixes, authorize.RequiresRole(admin.RoleAdmin)),
		func(c *gin.Context) {
			allowed := allowedMethods(patterns, c.Request.URL.Path)
			if hasPrefix(c.Request.URL.Path, mountedPrefixes) {
				if len(allowed) == 0 {
					http.NotFound(c.Writer, c.Request)
					return
				}
				methodNotAllowed(c, allowed)
				return
			}
			// The root serves a catch-all GET for the single page application, so every other
			// method is reported as not allowed rather than not found.
			if c.Request.Method != http.MethodGet {
				methodNotAllowed(c, sortMethods(append(allowed, http.MethodGet)))
				return
			}
			spa(c.Writer, c.Request)
		},
	)

	return r
}

// timeout cancels the request context after the given duration and answers
// 504 Gateway Timeout once the deadline has passed.
func timeout(d time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), d)
		defer func() {
			cancel()
			if ctx.Err() == context.DeadlineExceeded {
				c.Writer.WriteHeader(http.StatusGatewayTimeout)
			}
		}()

		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

// methodNotAllowed answers 405 Method Not Allowed with an empty body, advertising each allowed
// method in its own Allow header as the source router did.
func methodNotAllowed(c *gin.Context, allowed []string) {
	for _, m := range allowed {
		c.Writer.Header().Add("Allow", m)
	}
	c.Status(http.StatusMethodNotAllowed)
	c.Writer.Write(nil)
}

// routePattern is a registered route split into path segments for matching.
type routePattern struct {
	segments []string
	method   string
}

// routePatterns snapshots the engine's route table once all routes are registered.
func routePatterns(engine *gin.Engine) []routePattern {
	routes := engine.Routes()
	sort.SliceStable(routes, func(i, j int) bool { return routes[i].Path < routes[j].Path })
	patterns := make([]routePattern, 0, len(routes))
	for _, route := range routes {
		patterns = append(patterns, routePattern{segments: pathSegments(route.Path), method: route.Method})
	}
	return patterns
}

// pathSegments splits a path on the separator, keeping the empty final segment a trailing slash
// produces. The source router treated "/auth/login" and "/auth/login/" as different paths, so
// collapsing them here would answer 405 where the source answered 404.
func pathSegments(p string) []string {
	return strings.Split(strings.TrimPrefix(p, "/"), "/")
}

// allowedMethods returns the methods registered for the routes matching path, ignoring the request
// method. Wildcard segments match any single segment, mirroring how the source router reported the
// methods available on the node it reached.
func allowedMethods(patterns []routePattern, path string) []string {
	segments := pathSegments(path)
	var allowed []string
	for _, pattern := range patterns {
		if !matchSegments(pattern.segments, segments) {
			continue
		}
		if !slices.Contains(allowed, pattern.method) {
			allowed = append(allowed, pattern.method)
		}
	}
	return sortMethods(allowed)
}

// methodOrder is the order the Allow headers are emitted in. The source router derived the order
// from a map iteration and so varied it between identical requests; this is the order it produced
// most of the time, made deterministic.
var methodOrder = []string{
	http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
	http.MethodPatch, http.MethodDelete, http.MethodConnect, http.MethodOptions, http.MethodTrace,
}

func sortMethods(methods []string) []string {
	sort.SliceStable(methods, func(i, j int) bool {
		return slices.Index(methodOrder, methods[i]) < slices.Index(methodOrder, methods[j])
	})
	return methods
}

func matchSegments(pattern, segments []string) bool {
	if len(pattern) != len(segments) {
		return false
	}
	for i, p := range pattern {
		if strings.HasPrefix(p, ":") {
			if segments[i] == "" {
				return false
			}
			continue
		}
		if p != segments[i] {
			return false
		}
	}
	return true
}

// hasPrefix reports whether path equals or is nested below one of the given prefixes.
func hasPrefix(p string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			return true
		}
	}
	return false
}

// onlyBelow runs the given handler for requests below one of the prefixes and skips it otherwise.
func onlyBelow(prefixes []string, h gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		if hasPrefix(c.Request.URL.Path, prefixes) {
			h(c)
			return
		}
		c.Next()
	}
}

// corsConfig returns the CORS middleware. Preflight answers echo the requested method and header
// list instead of advertising the configured sets, and end the chain with an empty 200, which is
// the contract the source enforced.
func corsConfig() gin.HandlerFunc {
	// Basic CORS
	// for more ideas, see: https://developer.github.com/v3/#cross-origin-resource-sharing
	allowedMethods := []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	allowedHeaders := []string{"Origin", "Accept", "Authorization", "Content-Type", "X-Csrf-Token"}
	exposedHeaders := []string{"Link"}
	// Maximum value not ignored by any of major browsers
	const maxAge = 86400

	return func(c *gin.Context) {
		r := c.Request
		headers := c.Writer.Header()
		origin := r.Header.Get("Origin")
		reqMethod := r.Header.Get("Access-Control-Request-Method")

		if r.Method == http.MethodOptions && reqMethod != "" {
			headers.Add("Vary", "Origin")
			headers.Add("Vary", "Access-Control-Request-Method")
			headers.Add("Vary", "Access-Control-Request-Headers")

			reqHeaders := parseHeaderList(r.Header.Get("Access-Control-Request-Headers"))
			if origin != "" && methodAllowed(allowedMethods, reqMethod) && headersAllowed(allowedHeaders, reqHeaders) {
				headers.Set("Access-Control-Allow-Origin", "*")
				headers.Set("Access-Control-Allow-Methods", strings.ToUpper(reqMethod))
				if len(reqHeaders) > 0 {
					headers.Set("Access-Control-Allow-Headers", strings.Join(reqHeaders, ", "))
				}
				headers.Set("Access-Control-Allow-Credentials", "true")
				headers.Set("Access-Control-Max-Age", strconv.Itoa(maxAge))
			}
			c.AbortWithStatus(http.StatusOK)
			return
		}

		headers.Add("Vary", "Origin")
		if origin != "" && methodAllowed(allowedMethods, r.Method) {
			headers.Set("Access-Control-Allow-Origin", "*")
			headers.Set("Access-Control-Expose-Headers", strings.Join(exposedHeaders, ", "))
			headers.Set("Access-Control-Allow-Credentials", "true")
		}
		c.Next()
	}
}

// parseHeaderList splits and canonicalises an Access-Control-Request-Headers value.
func parseHeaderList(list string) []string {
	var out []string
	for _, part := range strings.Split(list, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, http.CanonicalHeaderKey(part))
	}
	return out
}

// methodAllowed reports whether method may be used cross-origin. OPTIONS is always permitted
// because it carries the preflight itself.
func methodAllowed(allowed []string, method string) bool {
	method = strings.ToUpper(method)
	return method == http.MethodOptions || slices.Contains(allowed, method)
}

func headersAllowed(allowed, requested []string) bool {
	for _, h := range requested {
		if !slices.Contains(allowed, h) {
			return false
		}
	}
	return true
}

// SPAHandler serves the public Single Page Application.
func SPAHandler(publicDir string) http.HandlerFunc {
	handler := http.FileServer(http.Dir(publicDir))
	return func(w http.ResponseWriter, r *http.Request) {
		indexPage := path.Join(publicDir, "index.html")
		serviceWorker := path.Join(publicDir, "service-worker.js")

		requestedAsset := path.Join(publicDir, r.URL.Path)
		if strings.Contains(requestedAsset, "service-worker.js") {
			requestedAsset = serviceWorker
		}
		if _, err := os.Stat(requestedAsset); err != nil {
			http.ServeFile(w, r, indexPage)
			return
		}
		handler.ServeHTTP(w, r)
	}
}
