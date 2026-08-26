package app

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"

	"github.com/dhax/go-base/auth/jwt"
	"github.com/dhax/go-base/auth/pwdless"
	"github.com/dhax/go-base/logging"
	"github.com/dhax/go-base/models"
)

const testSecret = "OjOHjJs1VvhuzIWqttTtNh7Y81xKgDatiopCUKMoKL0StwMb/LsBQLJ+AM6zq6WbherxmJGtPncQ3OsWPHdOTw=="

var tokenAuth *jwt.TokenAuth

var profileUpdatedAt = time.Date(2020, time.January, 2, 3, 4, 5, 0, time.UTC)

const profileJSON = "{\"updated_at\":\"2020-01-02T03:04:05Z\",\"theme\":\"default\"}\n"

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

type mockAppAccountStore struct {
	account        *pwdless.Account
	getErr         error
	updateErr      error
	deleteErr      error
	updateTokenErr error
	deleteTokenErr error
	deleteTokenHit bool
}

func (s *mockAppAccountStore) Get(id int) (*pwdless.Account, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	return s.account, nil
}

func (s *mockAppAccountStore) Update(a *pwdless.Account) error { return s.updateErr }
func (s *mockAppAccountStore) Delete(a *pwdless.Account) error { return s.deleteErr }
func (s *mockAppAccountStore) UpdateToken(t *jwt.Token) error  { return s.updateTokenErr }

func (s *mockAppAccountStore) DeleteToken(t *jwt.Token) error {
	s.deleteTokenHit = true
	return s.deleteTokenErr
}

type mockProfileStore struct {
	profile   *models.Profile
	getErr    error
	updateErr error
	updateHit bool
}

func (s *mockProfileStore) Get(accountID int) (*models.Profile, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	return s.profile, nil
}

func (s *mockProfileStore) Update(p *models.Profile) error {
	s.updateHit = true
	return s.updateErr
}

// appServer mounts the app router at /api behind the same access token chain api.New builds.
func appServer(t *testing.T, as AccountStore, ps ProfileStore) *httptest.Server {
	t.Helper()
	r := gin.New()
	r.RedirectTrailingSlash = false
	r.Use(logging.NewStructuredLogger(logging.NewLogger()))
	protected := r.Group("")
	protected.Use(tokenAuth.Verifier())
	protected.Use(jwt.Authenticator)
	a := &API{Account: NewAccountResource(as), Profile: NewProfileResource(ps)}
	a.Router(protected.Group("/api"))
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)
	return ts
}

func userToken(t *testing.T) string {
	t.Helper()
	token, err := tokenAuth.CreateJWT(jwt.AppClaims{ID: 1, Sub: "user", Roles: []string{"user"}})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func request(t *testing.T, ts *httptest.Server, method, path, token, contentType, body string) (*http.Response, string) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, ts.URL+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "BEARER "+token)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(out)
}

func fixtures() (*mockAppAccountStore, *mockProfileStore) {
	return &mockAppAccountStore{
			account: &pwdless.Account{
				ID: 1, Email: "user@example.com", Name: "user", Active: true,
				Token: []jwt.Token{{ID: 3, Token: "t3", Identifier: "Chrome on Linux"}},
			},
		}, &mockProfileStore{
			profile: &models.Profile{ID: 1, AccountID: 1, Theme: "default", UpdatedAt: profileUpdatedAt},
		}
}

// TestAppAccountPrefix pins the /api/account mount point and its trailing slash twin.
func TestAppAccountPrefix(t *testing.T) {
	as, ps := fixtures()
	ts := appServer(t, as, ps)
	token := userToken(t)

	for _, path := range []string{"/api/account", "/api/account/"} {
		resp, body := request(t, ts, http.MethodGet, path, token, "", "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status: want 200, got %d (%s)", path, resp.StatusCode, body)
		}
		if got := resp.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("%s: content type: want application/json, got %q", path, got)
		}
		if !strings.Contains(body, "\"email\":\"user@example.com\"") || !strings.HasSuffix(body, "\n") {
			t.Errorf("%s: body: want the account envelope ending in a newline, got %q", path, body)
		}
	}
}

// TestAppProfilePrefix pins that the profile router is mounted as a sibling of account rather
// than nested beneath it. The stale committed routes.md documents the nested layout, so the
// tempting wrong choice is to follow the document instead of the code.
func TestAppProfilePrefix(t *testing.T) {
	as, ps := fixtures()
	ts := appServer(t, as, ps)
	token := userToken(t)

	for _, path := range []string{"/api/profile", "/api/profile/"} {
		resp, body := request(t, ts, http.MethodGet, path, token, "", "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status: want 200, got %d (%s)", path, resp.StatusCode, body)
		}
		if want := profileJSON; body != want {
			t.Errorf("%s: body: want %q, got %q", path, want, body)
		}
	}
}

// TestAppAccountUnauthenticated pins that the chain in front of /api rejects anonymous callers.
func TestAppAccountUnauthenticated(t *testing.T) {
	as, ps := fixtures()
	ts := appServer(t, as, ps)

	resp, body := request(t, ts, http.MethodGet, "/api/account", "", "", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status: want 401, got %d", resp.StatusCode)
	}
	if want := "{\"status\":\"Unauthorized\",\"error\":\"token unauthorized\"}\n"; body != want {
		t.Errorf("body: want %q, got %q", want, body)
	}
}

// TestAppAccountCtxStoreFailure pins accountCtx's own 401, which is emitted by this package
// rather than by the token chain and therefore carries no "error" member.
func TestAppAccountCtxStoreFailure(t *testing.T) {
	as, ps := fixtures()
	as.getErr = errors.New("gone")
	ts := appServer(t, as, ps)

	resp, body := request(t, ts, http.MethodGet, "/api/account", userToken(t), "", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status: want 401, got %d", resp.StatusCode)
	}
	if want := "{\"status\":\"Unauthorized\"}\n"; body != want {
		t.Errorf("body: want %q, got %q", want, body)
	}
}

// TestAppProfileCtxStoreFailure pins profileCtx's 500 branch.
func TestAppProfileCtxStoreFailure(t *testing.T) {
	as, ps := fixtures()
	ps.getErr = errors.New("gone")
	ts := appServer(t, as, ps)

	resp, body := request(t, ts, http.MethodGet, "/api/profile", userToken(t), "", "")
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status: want 500, got %d", resp.StatusCode)
	}
	if want := "{\"status\":\"Internal Server Error\"}\n"; body != want {
		t.Errorf("body: want %q, got %q", want, body)
	}
}

// TestProfileUpdateMissingReturnQuirk pins an upstream bug that must survive the migration.
// profile update renders the 422 envelope on a decode failure but does not return, so it goes on
// to update the store and append a second JSON document to the same 422 response. Adding the
// missing return would be an improvement, and improvements are regressions against the source.
func TestProfileUpdateMissingReturnQuirk(t *testing.T) {
	as, ps := fixtures()
	ts := appServer(t, as, ps)

	resp, body := request(t, ts, http.MethodPut, "/api/profile", userToken(t), "application/json", "{not json")

	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("status: want 422, got %d", resp.StatusCode)
	}
	if !strings.HasPrefix(body, `{"status":"Unprocessable Entity","error":"invalid character`) {
		t.Errorf("body: want the 422 envelope first, got %q", body)
	}
	if !strings.HasSuffix(body, profileJSON) {
		t.Errorf("body: want the profile document appended after the envelope, got %q", body)
	}
	if !ps.updateHit {
		t.Error("store update: want the handler to fall through to the store despite the bind error")
	}
}

// TestAccountTokenRoutes pins the nested /token/:tokenID parameter seam.
func TestAccountTokenRoutes(t *testing.T) {
	as, ps := fixtures()
	ts := appServer(t, as, ps)
	token := userToken(t)

	for _, path := range []string{"/api/account/token/3", "/api/account/token/3/"} {
		resp, body := request(t, ts, http.MethodDelete, path, token, "", "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status: want 200, got %d (%s)", path, resp.StatusCode, body)
		}
		if body != "{}\n" {
			t.Errorf("%s: body: want %q, got %q", path, "{}\n", body)
		}
	}
	if !as.deleteTokenHit {
		t.Error("delete token: want the store to be reached")
	}

	resp, body := request(t, ts, http.MethodDelete, "/api/account/token/nope", token, "", "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status: want 400, got %d", resp.StatusCode)
	}
	if want := "{\"status\":\"Bad Request\"}\n"; body != want {
		t.Errorf("body: want %q, got %q", want, body)
	}
}

// TestDeleteTokenIgnoresStoreError pins a second upstream quirk: deleteToken discards the error
// returned by the store, so a failing delete is still reported to the client as success.
func TestDeleteTokenIgnoresStoreError(t *testing.T) {
	as, ps := fixtures()
	as.deleteTokenErr = errors.New("delete failed")
	ts := appServer(t, as, ps)

	resp, body := request(t, ts, http.MethodDelete, "/api/account/token/3", userToken(t), "", "")

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: want 200, got %d", resp.StatusCode)
	}
	if body != "{}\n" {
		t.Errorf("body: want %q, got %q", "{}\n", body)
	}
}

// TestAccountDeleteRespondsEmptyObject pins the NoBody rendering on the app side too.
func TestAccountDeleteRespondsEmptyObject(t *testing.T) {
	as, ps := fixtures()
	ts := appServer(t, as, ps)

	resp, body := request(t, ts, http.MethodDelete, "/api/account", userToken(t), "", "")

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: want 200, got %d", resp.StatusCode)
	}
	if body != "{}\n" {
		t.Errorf("body: want %q, got %q", "{}\n", body)
	}
}

// TestProfileUpdateIgnoresContentType pins that the body is decoded as JSON regardless of the
// declared content type, which is what the source router's forced content type produced.
func TestProfileUpdateIgnoresContentType(t *testing.T) {
	as, ps := fixtures()
	ts := appServer(t, as, ps)

	resp, body := request(t, ts, http.MethodPut, "/api/profile", userToken(t), "text/plain", `{"theme":"dark"}`)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: want 200, got %d (%s)", resp.StatusCode, body)
	}
	if want := "{\"updated_at\":\"2020-01-02T03:04:05Z\",\"theme\":\"dark\"}\n"; body != want {
		t.Errorf("body: want %q, got %q", want, body)
	}
}
