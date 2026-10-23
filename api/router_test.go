package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dhax/go-base/api/admin"
	"github.com/dhax/go-base/api/app"
	"github.com/dhax/go-base/auth/jwt"
	"github.com/dhax/go-base/auth/pwdless"
	"github.com/dhax/go-base/database"
	"github.com/dhax/go-base/email"
	"github.com/dhax/go-base/logging"
	"github.com/dhax/go-base/models"
	"github.com/spf13/viper"
)

const seamJWTSecret = "OjOHjJs1VvhuzIWqttTtNh7Y81xKgDatiopCUKMoKL0StwMb/LsBQLJ+AM6zq6WbherxmJGtPncQ3OsWPHdOTw=="

type seamAdminStore struct{}

func (s seamAdminStore) List(*database.AccountFilter) ([]pwdless.Account, int, error) {
	return []pwdless.Account{}, 0, nil
}
func (s seamAdminStore) Create(*pwdless.Account) error { return nil }
func (s seamAdminStore) Get(id int) (*pwdless.Account, error) {
	return &pwdless.Account{ID: id, Active: true}, nil
}
func (s seamAdminStore) Update(*pwdless.Account) error { return nil }
func (s seamAdminStore) Delete(*pwdless.Account) error { return nil }

type seamAppStore struct{}

func (s seamAppStore) Get(id int) (*pwdless.Account, error) {
	return &pwdless.Account{ID: id, Active: true}, nil
}
func (s seamAppStore) Update(*pwdless.Account) error { return nil }
func (s seamAppStore) Delete(*pwdless.Account) error { return nil }
func (s seamAppStore) UpdateToken(*jwt.Token) error  { return nil }
func (s seamAppStore) DeleteToken(*jwt.Token) error  { return nil }

type seamProfileStore struct{}

func (s seamProfileStore) Get(accountID int) (*models.Profile, error) {
	return &models.Profile{ID: accountID, AccountID: accountID}, nil
}
func (s seamProfileStore) Update(p *models.Profile) error { return nil }

func newSeamServer(t *testing.T) (*httptest.Server, *pwdless.Resource) {
	t.Helper()

	viper.Set("auth_login_url", "http://localhost/login")
	viper.Set("auth_login_token_length", 8)
	viper.Set("auth_login_token_expiry", "11m")
	viper.Set("auth_jwt_secret", seamJWTSecret)
	viper.Set("auth_jwt_expiry", "15m")
	viper.Set("auth_jwt_refresh_expiry", "1h")
	viper.Set("log_level", "error")

	purge := func() error { return nil }
	authResource, err := pwdless.NewResource(&pwdless.MockAuthStore{PurgeExpiredTokenFn: purge}, email.NewMockMailer())
	if err != nil {
		t.Fatalf("NewResource: %v", err)
	}

	adminAPI := &admin.API{Accounts: admin.NewAccountResource(seamAdminStore{})}
	appAPI := &app.API{
		Account: app.NewAccountResource(seamAppStore{}),
		Profile: app.NewProfileResource(seamProfileStore{}),
	}

	ts := httptest.NewServer(newRouter(false, logging.NewLogger(), authResource, adminAPI, appAPI))
	t.Cleanup(ts.Close)
	return ts, authResource
}

func seamToken(t *testing.T, rs *pwdless.Resource, roles []string) string {
	t.Helper()
	tok, err := rs.TokenAuth.CreateJWT(jwt.AppClaims{ID: 1, Sub: "seam@example.com", Roles: roles})
	if err != nil {
		t.Fatalf("CreateJWT: %v", err)
	}
	return tok
}

func seamRequest(t *testing.T, ts *httptest.Server, method, path, token string) (int, string, string) {
	t.Helper()
	req, err := http.NewRequest(method, ts.URL+path, nil)
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
	return resp.StatusCode, resp.Header.Get("Content-Type"), string(body)
}

// TestNotFoundChainRunsAdminRoleGuard pins the ordering the source router gets for free by
// mounting a sub router: an unknown path below /admin is still refused by the role guard, so a
// non-admin sees 403 rather than the not found handler. Dropping the guard from the catch-all
// chain compiles, keeps every other test green, and is only visible over the wire.
func TestNotFoundChainRunsAdminRoleGuard(t *testing.T) {
	ts, rs := newSeamServer(t)
	user := seamToken(t, rs, []string{"user"})
	adm := seamToken(t, rs, []string{"admin"})

	for _, path := range []string{"/admin/nope", "/admin/a/b/c", "/admin/accounts/1/nope"} {
		status, ctype, body := seamRequest(t, ts, http.MethodGet, path, user)
		if status != http.StatusForbidden {
			t.Errorf("GET %s as user: status = %d, want %d", path, status, http.StatusForbidden)
		}
		if ctype != "application/json" {
			t.Errorf("GET %s as user: content type = %q, want %q", path, ctype, "application/json")
		}
		if want := "{\"status\":\"Forbidden\"}\n"; body != want {
			t.Errorf("GET %s as user: body = %q, want %q", path, body, want)
		}
	}

	status, _, body := seamRequest(t, ts, http.MethodGet, "/admin/nope", adm)
	if status != http.StatusNotFound {
		t.Errorf("GET /admin/nope as admin: status = %d, want %d", status, http.StatusNotFound)
	}
	if want := "404 page not found\n"; body != want {
		t.Errorf("GET /admin/nope as admin: body = %q, want %q", body, want)
	}

	status, _, body = seamRequest(t, ts, http.MethodGet, "/admin/nope", "")
	if status != http.StatusUnauthorized {
		t.Errorf("GET /admin/nope anonymous: status = %d, want %d", status, http.StatusUnauthorized)
	}
	if want := "{\"status\":\"Unauthorized\",\"error\":\"token unauthorized\"}\n"; body != want {
		t.Errorf("GET /admin/nope anonymous: body = %q, want %q", body, want)
	}

	status, _, _ = seamRequest(t, ts, http.MethodGet, "/api/nope", user)
	if status != http.StatusNotFound {
		t.Errorf("GET /api/nope as user: status = %d, want %d", status, http.StatusNotFound)
	}
}

// TestNotFoundChainMethodNotAllowed pins that the catch-all decides 405 only after the
// authenticator has run. Letting the router answer method not allowed turns the anonymous
// case into a 405 and loses the Allow headers the source router emitted.
func TestNotFoundChainMethodNotAllowed(t *testing.T) {
	ts, rs := newSeamServer(t)
	user := seamToken(t, rs, []string{"user"})

	req, err := http.NewRequest(http.MethodPatch, ts.URL+"/api/account", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "BEARER "+user)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("PATCH /api/account authenticated: status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
	allow := resp.Header.Values("Allow")
	want := []string{"GET", "PUT", "DELETE"}
	if len(allow) != len(want) {
		t.Fatalf("Allow = %v, want one header per method %v", allow, want)
	}
	for i := range want {
		if allow[i] != want[i] {
			t.Errorf("Allow[%d] = %q, want %q", i, allow[i], want[i])
		}
	}

	status, _, _ := seamRequest(t, ts, http.MethodPatch, "/api/account", "")
	if status != http.StatusUnauthorized {
		t.Errorf("PATCH /api/account anonymous: status = %d, want %d", status, http.StatusUnauthorized)
	}
}

// TestRouterTrailingSlashAndRoot pins that no redirect is introduced where the source router
// answered directly, and that the root catch-all still serves the single page application.
func TestRouterTrailingSlashAndRoot(t *testing.T) {
	ts, _ := newSeamServer(t)

	status, _, _ := seamRequest(t, ts, http.MethodPost, "/auth/login/", "")
	if status != http.StatusNotFound {
		t.Errorf("POST /auth/login/: status = %d, want %d", status, http.StatusNotFound)
	}

	status, _, body := seamRequest(t, ts, http.MethodGet, "/healthz", "")
	if status != http.StatusOK || body != "ok" {
		t.Errorf("GET /healthz: status = %d body = %q, want 200 %q", status, body, "ok")
	}

	status, _, _ = seamRequest(t, ts, http.MethodPost, "/anything", "")
	if status != http.StatusMethodNotAllowed {
		t.Errorf("POST /anything: status = %d, want %d", status, http.StatusMethodNotAllowed)
	}
}
