package jwt

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"

	"github.com/dhax/go-base/logging"
)

// testSecret is a throwaway 88 character secret, long enough to pass NewTokenAuth's length check.
const testSecret = "OjOHjJs1VvhuzIWqttTtNh7Y81xKgDatiopCUKMoKL0StwMb/LsBQLJ+AM6zq6WbherxmJGtPncQ3OsWPHdOTw=="

var tokenAuth *TokenAuth

func TestMain(m *testing.M) {
	viper.SetDefault("auth_jwt_secret", testSecret)
	viper.SetDefault("auth_jwt_expiry", "15m")
	viper.SetDefault("auth_jwt_refresh_expiry", "1h")
	viper.SetDefault("log_level", "error")

	var err error
	tokenAuth, err = NewTokenAuth()
	if err != nil {
		panic(err)
	}

	gin.SetMode(gin.TestMode)
	os.Exit(m.Run())
}

// protectedServer starts a real http server behind the access token chain, which is
// the seam replacing chi's jwtauth.Verifier + the project's own Authenticator.
func protectedServer(t *testing.T) *httptest.Server {
	t.Helper()
	r := gin.New()
	r.Use(logging.NewStructuredLogger(logging.NewLogger()))
	r.Use(tokenAuth.Verifier())
	r.Use(Authenticator)
	r.GET("/protected", func(c *gin.Context) {
		claims := ClaimsFromCtx(c.Request.Context())
		c.String(http.StatusOK, claims.Sub)
	})
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)
	return ts
}

func probe(t *testing.T, ts *httptest.Server, mutate func(*http.Request)) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, ts.URL+"/protected", nil)
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(req)
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

// TestVerifierRejectsUnauthenticated pins the error envelope of the access token chain
// over the wire: status, content type and the trailing newline chi's render.JSON emitted.
func TestVerifierRejectsUnauthenticated(t *testing.T) {
	ts := protectedServer(t)

	resp, body := probe(t, ts, nil)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status: want 401, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("content type: want application/json, got %q", got)
	}
	if want := "{\"status\":\"Unauthorized\",\"error\":\"token unauthorized\"}\n"; body != want {
		t.Errorf("body: want %q, got %q", want, body)
	}
}

// TestVerifierAcceptsBearerHeader pins the Authorization header extractor, which must keep
// chi jwtauth's case-insensitive "BEARER " prefix handling.
func TestVerifierAcceptsBearerHeader(t *testing.T) {
	ts := protectedServer(t)

	token, err := tokenAuth.CreateJWT(AppClaims{ID: 1, Sub: "seam", Roles: []string{"user"}})
	if err != nil {
		t.Fatal(err)
	}

	for _, prefix := range []string{"Bearer ", "BEARER ", "bearer "} {
		resp, body := probe(t, ts, func(r *http.Request) {
			r.Header.Set("Authorization", prefix+token)
		})
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%q: status: want 200, got %d (%s)", prefix, resp.StatusCode, body)
		}
		if body != "seam" {
			t.Errorf("%q: body: want %q, got %q", prefix, "seam", body)
		}
	}
}

// TestVerifierAcceptsJWTCookie pins the second extractor. chi's jwtauth.Verifier wires
// TokenFromHeader and TokenFromCookie only, so dropping the cookie source would still compile.
func TestVerifierAcceptsJWTCookie(t *testing.T) {
	ts := protectedServer(t)

	token, err := tokenAuth.CreateJWT(AppClaims{ID: 2, Sub: "cookie", Roles: []string{"user"}})
	if err != nil {
		t.Fatal(err)
	}

	resp, body := probe(t, ts, func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: "jwt", Value: token})
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: want 200, got %d (%s)", resp.StatusCode, body)
	}
	if body != "cookie" {
		t.Errorf("body: want %q, got %q", "cookie", body)
	}
}

// TestVerifierIgnoresQueryParameter pins the absence of the third extractor: chi's
// jwtauth.Verifier deliberately does not wire TokenFromQuery, so a ?jwt= token is not accepted.
func TestVerifierIgnoresQueryParameter(t *testing.T) {
	ts := protectedServer(t)

	token, err := tokenAuth.CreateJWT(AppClaims{ID: 3, Sub: "query", Roles: []string{"user"}})
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/protected?jwt="+token, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status: want 401, got %d", resp.StatusCode)
	}
}

// TestAuthenticatorRejectsExpiredToken pins an upstream quirk that survives the migration.
// The verifier parses without validating and then validates itself, stashing a generic error in
// the request context, so Authenticator answers on its first branch with ErrTokenUnauthorized and
// its ErrTokenExpired branch is unreachable through this chain. Reporting "token expired" here
// would read like an improvement but is a wire regression against the source.
func TestAuthenticatorRejectsExpiredToken(t *testing.T) {
	ts := protectedServer(t)

	_, token, err := tokenAuth.JwtAuth.Encode(map[string]any{
		"id":    4,
		"sub":   "expired",
		"roles": []string{"user"},
		"iat":   time.Now().Add(-2 * time.Hour).Unix(),
		"exp":   time.Now().Add(-time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, body := probe(t, ts, func(r *http.Request) {
		r.Header.Set("Authorization", "BEARER "+token)
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status: want 401, got %d", resp.StatusCode)
	}
	if want := "{\"status\":\"Unauthorized\",\"error\":\"token unauthorized\"}\n"; body != want {
		t.Errorf("body: want %q, got %q", want, body)
	}
}

// TestAuthenticatorRejectsIncompleteClaims pins the third failure surface: a well formed,
// unexpired token whose payload does not satisfy AppClaims.ParseClaims.
func TestAuthenticatorRejectsIncompleteClaims(t *testing.T) {
	ts := protectedServer(t)

	_, token, err := tokenAuth.JwtAuth.Encode(map[string]any{
		"sub": "no-id",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, body := probe(t, ts, func(r *http.Request) {
		r.Header.Set("Authorization", "BEARER "+token)
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status: want 401, got %d", resp.StatusCode)
	}
	if want := "{\"status\":\"Unauthorized\",\"error\":\"invalid access token\"}\n"; body != want {
		t.Errorf("body: want %q, got %q", want, body)
	}
}

// TestAuthenticatorRejectsForeignSignature pins that the HS256 key is actually checked.
func TestAuthenticatorRejectsForeignSignature(t *testing.T) {
	ts := protectedServer(t)

	foreign := NewJWTAuth("HS256", []byte("this-is-a-different-secret-of-sufficient-length"))
	_, token, err := foreign.Encode(map[string]any{
		"id":    5,
		"sub":   "forged",
		"roles": []string{"user"},
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, _ := probe(t, ts, func(r *http.Request) {
		r.Header.Set("Authorization", "BEARER "+token)
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status: want 401, got %d", resp.StatusCode)
	}
}

// TestRefreshChainUsesRefreshClaims pins that AuthenticateRefreshJWT reads the refresh
// token claim shape and exposes the raw token through RefreshTokenFromCtx.
func TestRefreshChainUsesRefreshClaims(t *testing.T) {
	r := gin.New()
	r.Use(logging.NewStructuredLogger(logging.NewLogger()))
	r.Use(tokenAuth.Verifier())
	r.Use(AuthenticateRefreshJWT)
	r.GET("/refresh", func(c *gin.Context) {
		c.String(http.StatusOK, RefreshTokenFromCtx(c.Request.Context()))
	})
	ts := httptest.NewServer(r)
	defer ts.Close()

	token, err := tokenAuth.CreateRefreshJWT(RefreshClaims{ID: 6, Token: "refresh-token-value"})
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/refresh", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "BEARER "+token)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: want 200, got %d (%s)", resp.StatusCode, body)
	}
	if string(body) != "refresh-token-value" {
		t.Errorf("refresh token: want %q, got %q", "refresh-token-value", body)
	}
}

// TestRefreshChainRejectsAccessToken pins that an access token cannot be replayed on the
// refresh chain: it carries no "token" claim, so RefreshClaims.ParseClaims fails.
func TestRefreshChainRejectsAccessToken(t *testing.T) {
	r := gin.New()
	r.Use(logging.NewStructuredLogger(logging.NewLogger()))
	r.Use(tokenAuth.Verifier())
	r.Use(AuthenticateRefreshJWT)
	r.GET("/refresh", func(c *gin.Context) { c.String(http.StatusOK, "reached") })
	ts := httptest.NewServer(r)
	defer ts.Close()

	access, err := tokenAuth.CreateJWT(AppClaims{ID: 7, Sub: "access", Roles: []string{"user"}})
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/refresh", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "BEARER "+access)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status: want 401, got %d", resp.StatusCode)
	}
	if want := "{\"status\":\"Unauthorized\",\"error\":\"invalid refresh token\"}\n"; string(body) != want {
		t.Errorf("body: want %q, got %q", want, body)
	}
}

// TestNewTokenAuthRejectsWeakSecrets pins the secret policy carried over unchanged.
func TestNewTokenAuthRejectsWeakSecrets(t *testing.T) {
	original := viper.GetString("auth_jwt_secret")
	defer viper.Set("auth_jwt_secret", original)

	for _, tc := range []struct {
		secret string
		want   error
	}{
		{"", ErrWeakSecret},
		{"secret", ErrWeakSecret},
		{"CHANGE-ME", ErrWeakSecret},
		{"your-secret-key", ErrWeakSecret},
		{"short-but-not-a-known-default", ErrSecretTooShort},
	} {
		viper.Set("auth_jwt_secret", tc.secret)
		if _, err := NewTokenAuth(); err != tc.want {
			t.Errorf("secret %q: want %v, got %v", tc.secret, tc.want, err)
		}
	}
}
