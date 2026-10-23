package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func do(t *testing.T, ts *httptest.Server, method, path string, headers map[string]string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, ts.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(body)
}

// TestSPAHandlerServesFilesAndFallsBack pins the single page application fallback: an existing
// file is served as itself and any unknown path is answered with index.html rather than a 404.
func TestSPAHandlerServesFilesAndFallsBack(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>index</html>"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte("console.log(1)"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "service-worker.js"), []byte("// sw"), 0644); err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(SPAHandler(dir))
	defer ts.Close()

	resp, body := do(t, ts, http.MethodGet, "/app.js", nil)
	if resp.StatusCode != http.StatusOK || body != "console.log(1)" {
		t.Errorf("existing file: want 200 and the file bytes, got %d %q", resp.StatusCode, body)
	}

	resp, body = do(t, ts, http.MethodGet, "/some/deep/route", nil)
	if resp.StatusCode != http.StatusOK || body != "<html>index</html>" {
		t.Errorf("unknown path: want the index fallback, got %d %q", resp.StatusCode, body)
	}

	resp, body = do(t, ts, http.MethodGet, "/service-worker.js", nil)
	if resp.StatusCode != http.StatusOK || body != "// sw" {
		t.Errorf("service worker at the root: want 200 and the file bytes, got %d %q", resp.StatusCode, body)
	}
}

// TestSPAHandlerNestedServiceWorkerQuirk pins an upstream bug. A nested service-worker.js request
// is rewritten to the public root only for the existence check; the original URL is then handed to
// the file server, which does not find it and answers 404 instead of falling back to index.html.
func TestSPAHandlerNestedServiceWorkerQuirk(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>index</html>"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "service-worker.js"), []byte("// sw"), 0644); err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(SPAHandler(dir))
	defer ts.Close()

	resp, body := do(t, ts, http.MethodGet, "/nested/service-worker.js", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status: want 404, got %d", resp.StatusCode)
	}
	if body != "404 page not found\n" {
		t.Errorf("body: want the file server 404, got %q", body)
	}
}

// TestTimeoutMiddlewareRespondsGatewayTimeout pins the replacement for chi's Timeout middleware,
// including the 504 it writes once the request context deadline has passed.
func TestTimeoutMiddlewareRespondsGatewayTimeout(t *testing.T) {
	r := gin.New()
	r.Use(timeout(20 * time.Millisecond))
	r.GET("/slow", func(c *gin.Context) {
		<-c.Request.Context().Done()
	})
	ts := httptest.NewServer(r)
	defer ts.Close()

	resp, _ := do(t, ts, http.MethodGet, "/slow", nil)
	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Errorf("status: want 504, got %d", resp.StatusCode)
	}
}

// TestTimeoutMiddlewareKeepsGatewayTimeoutOnLatePanic pins the middleware order of the source router: a
// request that panics after its deadline has passed keeps the 504 the timeout middleware wrote, because the
// recoverer runs outside of it and can no longer change the status.
func TestTimeoutMiddlewareKeepsGatewayTimeoutOnLatePanic(t *testing.T) {
	r := gin.New()
	r.Use(recoverer)
	r.Use(timeout(20 * time.Millisecond))
	r.GET("/late", func(c *gin.Context) {
		<-c.Request.Context().Done()
		panic("late")
	})
	ts := httptest.NewServer(r)
	defer ts.Close()

	resp, body := do(t, ts, http.MethodGet, "/late", nil)
	if resp.StatusCode != http.StatusGatewayTimeout || body != "" {
		t.Errorf("want 504 and an empty body, got %d %q", resp.StatusCode, body)
	}
}

// TestTimeoutMiddlewarePassesFastRequests pins that the deadline does not disturb the normal path.
func TestTimeoutMiddlewarePassesFastRequests(t *testing.T) {
	r := gin.New()
	r.Use(timeout(time.Second))
	r.GET("/fast", func(c *gin.Context) { c.String(http.StatusOK, "done") })
	ts := httptest.NewServer(r)
	defer ts.Close()

	resp, body := do(t, ts, http.MethodGet, "/fast", nil)
	if resp.StatusCode != http.StatusOK || body != "done" {
		t.Errorf("want 200 and %q, got %d %q", "done", resp.StatusCode, body)
	}
}

// TestMethodNotAllowedAdvertisesEachMethod pins the 405 shape: an empty body and one Allow header
// per permitted method, which is how the source announced them. Joining them into a single
// comma separated header, or omitting the body write, changes the bytes on the wire.
func TestMethodNotAllowedAdvertisesEachMethod(t *testing.T) {
	r := gin.New()
	r.NoRoute(func(c *gin.Context) { methodNotAllowed(c, []string{"GET", "PUT", "DELETE"}) })
	ts := httptest.NewServer(r)
	defer ts.Close()

	resp, body := do(t, ts, http.MethodPatch, "/anything", nil)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status: want 405, got %d", resp.StatusCode)
	}
	if body != "" {
		t.Errorf("body: want empty, got %q", body)
	}
	got := resp.Header.Values("Allow")
	want := []string{"GET", "PUT", "DELETE"}
	if len(got) != len(want) {
		t.Fatalf("Allow headers: want %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Allow header %d: want %q, got %q", i, want[i], got[i])
		}
	}
}

// TestAllowedMethodsMatchesWildcardSegments pins the lookup that feeds the Allow header. The source
// reported the methods registered on the node it reached, including for routes whose path carries a
// parameter, so a matcher that only handled static paths would silently report none. A trailing
// slash is a different path, and the order is fixed because the source varied it between runs.
func TestAllowedMethodsMatchesWildcardSegments(t *testing.T) {
	r := gin.New()
	noop := func(c *gin.Context) {}
	r.GET("/healthz", noop)
	r.GET("/admin/accounts", noop)
	r.POST("/admin/accounts", noop)
	r.GET("/admin/accounts/:accountID", noop)
	r.PUT("/admin/accounts/:accountID", noop)
	r.DELETE("/admin/accounts/:accountID", noop)
	patterns := routePatterns(r)

	cases := []struct {
		path string
		want []string
	}{
		{"/healthz", []string{"GET"}},
		{"/admin/accounts", []string{"GET", "POST"}},
		{"/admin/accounts/7", []string{"GET", "PUT", "DELETE"}},
		{"/admin/accounts/7/", nil},
		{"/admin/nope", nil},
		{"/admin/accounts/7/deeper", nil},
	}
	for _, tc := range cases {
		got := allowedMethods(patterns, tc.path)
		if !slices.Equal(got, tc.want) {
			t.Errorf("allowedMethods(%q): want %v, got %v", tc.path, tc.want, got)
		}
	}
}

func TestHasPrefix(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/auth", true},
		{"/auth/login", true},
		{"/admin/accounts/1", true},
		{"/api/profile", true},
		{"/authorize", false},
		{"/apiary", false},
		{"/healthz", false},
		{"/", false},
	}
	for _, tc := range cases {
		if got := hasPrefix(tc.path, mountedPrefixes); got != tc.want {
			t.Errorf("hasPrefix(%q): want %v, got %v", tc.path, tc.want, got)
		}
	}
}

// TestOnlyBelowRunsHandlerOnlyUnderPrefix pins the guard that keeps the token chain attached to
// unmatched paths below /admin and /api while leaving the single page application untouched.
func TestOnlyBelowRunsHandlerOnlyUnderPrefix(t *testing.T) {
	var ran bool
	guard := onlyBelow(protectedPrefixes, func(c *gin.Context) {
		ran = true
		c.Next()
	})

	r := gin.New()
	r.Use(guard)
	r.NoRoute(func(c *gin.Context) { c.String(http.StatusOK, "reached") })
	ts := httptest.NewServer(r)
	defer ts.Close()

	ran = false
	do(t, ts, http.MethodGet, "/admin/nope", nil)
	if !ran {
		t.Error("below a protected prefix: want the wrapped handler to run")
	}

	ran = false
	do(t, ts, http.MethodGet, "/anything-else", nil)
	if ran {
		t.Error("outside the protected prefixes: want the wrapped handler skipped")
	}
}

// TestCORSPreflightEchoesRequest pins the CORS contract carried over from the source: a preflight
// ends the chain with an empty 200 and echoes the requested method and header list rather than
// advertising the configured sets. Off the shelf gin CORS middleware answers 204 and lists the
// configuration, so every assertion here is a seam.
func TestCORSPreflightEchoesRequest(t *testing.T) {
	r := gin.New()
	r.Use(corsConfig())
	r.GET("/healthz", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	ts := httptest.NewServer(r)
	defer ts.Close()

	resp, body := do(t, ts, http.MethodOptions, "/healthz", map[string]string{
		"Origin":                         "https://example.com",
		"Access-Control-Request-Method":  http.MethodGet,
		"Access-Control-Request-Headers": "Authorization",
	})

	if resp.StatusCode != http.StatusOK {
		t.Errorf("preflight status: want 200, got %d", resp.StatusCode)
	}
	if body != "" {
		t.Errorf("preflight body: want empty, got %q", body)
	}
	for header, want := range map[string]string{
		"Access-Control-Allow-Origin":      "*",
		"Access-Control-Allow-Methods":     "GET",
		"Access-Control-Allow-Headers":     "Authorization",
		"Access-Control-Allow-Credentials": "true",
		"Access-Control-Max-Age":           "86400",
	} {
		if got := resp.Header.Get(header); got != want {
			t.Errorf("%s: want %q, got %q", header, want, got)
		}
	}
	if got := resp.Header.Values("Vary"); len(got) != 3 {
		t.Errorf("Vary: want three headers, got %v", got)
	}
	if resp.Header.Get("Allow") != "" {
		t.Errorf("Allow: want no method advertisement on a preflight, got %q", resp.Header.Get("Allow"))
	}
}

// TestCORSPreflightOmitsHeadersWhenNoneRequested pins that the Allow-Headers member is absent
// rather than empty when the client asks for no headers.
func TestCORSPreflightOmitsHeadersWhenNoneRequested(t *testing.T) {
	r := gin.New()
	r.Use(corsConfig())
	r.POST("/auth/login", func(c *gin.Context) { c.Status(http.StatusOK) })
	ts := httptest.NewServer(r)
	defer ts.Close()

	resp, _ := do(t, ts, http.MethodOptions, "/auth/login", map[string]string{
		"Origin":                        "https://example.com",
		"Access-Control-Request-Method": http.MethodPost,
	})

	if got := resp.Header.Get("Access-Control-Allow-Methods"); got != "POST" {
		t.Errorf("allow methods: want POST, got %q", got)
	}
	if _, ok := resp.Header["Access-Control-Allow-Headers"]; ok {
		t.Errorf("allow headers: want the header absent, got %q", resp.Header.Get("Access-Control-Allow-Headers"))
	}
}

// TestCORSActualRequestHeaders pins the non preflight branch.
func TestCORSActualRequestHeaders(t *testing.T) {
	r := gin.New()
	r.Use(corsConfig())
	r.GET("/healthz", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	ts := httptest.NewServer(r)
	defer ts.Close()

	resp, body := do(t, ts, http.MethodGet, "/healthz", map[string]string{"Origin": "https://example.com"})

	if resp.StatusCode != http.StatusOK || body != "ok" {
		t.Errorf("want the request to pass through, got %d %q", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Access-Control-Expose-Headers"); got != "Link" {
		t.Errorf("expose headers: want Link, got %q", got)
	}
	if got := resp.Header.Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("allow credentials: want true, got %q", got)
	}
	if got := resp.Header.Values("Vary"); len(got) != 1 || got[0] != "Origin" {
		t.Errorf("Vary: want a single Origin, got %v", got)
	}
	if resp.Header.Get("Access-Control-Allow-Methods") != "" {
		t.Errorf("allow methods: want it absent outside a preflight, got %q", resp.Header.Get("Access-Control-Allow-Methods"))
	}
}

// TestCORSWithoutOriginIsInert pins that same-origin traffic gets no CORS members.
func TestCORSWithoutOriginIsInert(t *testing.T) {
	r := gin.New()
	r.Use(corsConfig())
	r.GET("/healthz", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	ts := httptest.NewServer(r)
	defer ts.Close()

	resp, _ := do(t, ts, http.MethodGet, "/healthz", nil)
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("allow origin: want it absent without an Origin request header, got %q", got)
	}
}
