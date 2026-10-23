package authorize

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"

	"github.com/dhax/go-base/auth/jwt"
	"github.com/dhax/go-base/logging"
)

const testSecret = "OjOHjJs1VvhuzIWqttTtNh7Y81xKgDatiopCUKMoKL0StwMb/LsBQLJ+AM6zq6WbherxmJGtPncQ3OsWPHdOTw=="

var tokenAuth *jwt.TokenAuth

func TestMain(m *testing.M) {
	viper.SetDefault("auth_jwt_secret", testSecret)
	viper.SetDefault("auth_jwt_expiry", "15m")
	viper.SetDefault("auth_jwt_refresh_expiry", "1h")
	viper.SetDefault("log_level", "error")

	var err error
	tokenAuth, err = jwt.NewTokenAuth()
	if err != nil {
		panic(err)
	}

	gin.SetMode(gin.TestMode)
	os.Exit(m.Run())
}

// roleServer starts a real server behind the full access token chain plus the role guard,
// which is the ordering RequiresRole depends on: it reads claims the Authenticator installed.
func roleServer(t *testing.T) *httptest.Server {
	t.Helper()
	r := gin.New()
	r.Use(logging.NewStructuredLogger(logging.NewLogger()))
	r.Use(tokenAuth.Verifier())
	r.Use(jwt.Authenticator)
	r.Use(RequiresRole("admin"))
	r.GET("/guarded", func(c *gin.Context) { c.String(http.StatusOK, "granted") })
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)
	return ts
}

func get(t *testing.T, ts *httptest.Server, token string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, ts.URL+"/guarded", nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "BEARER "+token)
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

// TestRequiresRoleForbidsMissingRole pins the 403 envelope over the wire. A role guard that
// silently let everyone through would still compile and still leave the inherited suite green.
func TestRequiresRoleForbidsMissingRole(t *testing.T) {
	ts := roleServer(t)

	token, err := tokenAuth.CreateJWT(jwt.AppClaims{ID: 1, Sub: "plain", Roles: []string{"user"}})
	if err != nil {
		t.Fatal(err)
	}

	resp, body := get(t, ts, token)

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status: want 403, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("content type: want application/json, got %q", got)
	}
	if want := "{\"status\":\"Forbidden\"}\n"; body != want {
		t.Errorf("body: want %q, got %q", want, body)
	}
}

// TestRequiresRoleAllowsMatchingRole pins the positive branch and that the guard hands off
// to the next handler rather than terminating the chain.
func TestRequiresRoleAllowsMatchingRole(t *testing.T) {
	ts := roleServer(t)

	token, err := tokenAuth.CreateJWT(jwt.AppClaims{ID: 2, Sub: "boss", Roles: []string{"user", "admin"}})
	if err != nil {
		t.Fatal(err)
	}

	resp, body := get(t, ts, token)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: want 200, got %d (%s)", resp.StatusCode, body)
	}
	if body != "granted" {
		t.Errorf("body: want %q, got %q", "granted", body)
	}
}

// TestRequiresRoleRunsAfterAuthentication pins the chain ordering: an unauthenticated request
// must be answered by the Authenticator with 401, never reach the role guard, and never panic
// inside ClaimsFromCtx, whose unchecked type assertion is an upstream quirk kept as is.
func TestRequiresRoleRunsAfterAuthentication(t *testing.T) {
	ts := roleServer(t)

	resp, body := get(t, ts, "")

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status: want 401, got %d", resp.StatusCode)
	}
	if want := "{\"status\":\"Unauthorized\",\"error\":\"token unauthorized\"}\n"; body != want {
		t.Errorf("body: want %q, got %q", want, body)
	}
}

func TestHasRole(t *testing.T) {
	if !hasRole("admin", []string{"user", "admin"}) {
		t.Error("hasRole: want true for a present role")
	}
	if hasRole("admin", []string{"user"}) {
		t.Error("hasRole: want false for an absent role")
	}
	if hasRole("admin", nil) {
		t.Error("hasRole: want false for nil roles")
	}
}
