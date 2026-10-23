package admin

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	validation "github.com/go-ozzo/ozzo-validation"
	"github.com/spf13/viper"

	"github.com/dhax/go-base/auth/jwt"
	"github.com/dhax/go-base/auth/pwdless"
	"github.com/dhax/go-base/database"
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

type mockAccountStore struct {
	accounts  []pwdless.Account
	listErr   error
	createErr error
	getErr    error
	updateErr error
	deleteErr error
}

func (s *mockAccountStore) List(f *database.AccountFilter) ([]pwdless.Account, int, error) {
	if s.listErr != nil {
		return nil, 0, s.listErr
	}
	return s.accounts, len(s.accounts), nil
}

func (s *mockAccountStore) Create(a *pwdless.Account) error { return s.createErr }

func (s *mockAccountStore) Get(id int) (*pwdless.Account, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	for i := range s.accounts {
		if s.accounts[i].ID == id {
			return &s.accounts[i], nil
		}
	}
	return nil, errors.New("account not found")
}

func (s *mockAccountStore) Update(a *pwdless.Account) error { return s.updateErr }
func (s *mockAccountStore) Delete(a *pwdless.Account) error { return s.deleteErr }

// adminServer mounts the admin router exactly as api.New does, behind the same access token
// chain and at the same /admin prefix, so the test fails if either the prefix or the chain moves.
func adminServer(t *testing.T, store AccountStore) *httptest.Server {
	t.Helper()
	r := gin.New()
	r.RedirectTrailingSlash = false
	r.Use(logging.NewStructuredLogger(logging.NewLogger()))
	protected := r.Group("")
	protected.Use(tokenAuth.Verifier())
	protected.Use(jwt.Authenticator)
	a := &API{Accounts: NewAccountResource(store)}
	a.Router(protected.Group("/admin"))
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)
	return ts
}

func adminToken(t *testing.T, roles ...string) string {
	t.Helper()
	token, err := tokenAuth.CreateJWT(jwt.AppClaims{ID: 1, Sub: "root", Roles: roles})
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

// TestAdminIndexPrefix pins the mount point. Mounting the admin router at the engine root, or at
// any other prefix, compiles and leaves the inherited suite green; only a live probe catches it.
func TestAdminIndexPrefix(t *testing.T) {
	ts := adminServer(t, &mockAccountStore{})
	token := adminToken(t, "admin")

	for _, path := range []string{"/admin", "/admin/"} {
		resp, body := request(t, ts, http.MethodGet, path, token, "", "")
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: status: want 200, got %d (%s)", path, resp.StatusCode, body)
		}
		if body != "Hello Admin" {
			t.Errorf("%s: body: want %q, got %q", path, "Hello Admin", body)
		}
	}
}

// TestAdminRequiresAdminRole pins that the role guard is mounted inside the admin router
// rather than dropped during the move to gin route groups.
func TestAdminRequiresAdminRole(t *testing.T) {
	ts := adminServer(t, &mockAccountStore{})

	resp, body := request(t, ts, http.MethodGet, "/admin", adminToken(t, "user"), "", "")
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status: want 403, got %d", resp.StatusCode)
	}
	if want := "{\"status\":\"Forbidden\"}\n"; body != want {
		t.Errorf("body: want %q, got %q", want, body)
	}

	resp, _ = request(t, ts, http.MethodGet, "/admin", "", "", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated status: want 401, got %d", resp.StatusCode)
	}
}

// TestAccountsListEnvelope pins the list response shape and the trailing newline that
// chi's render.JSON produced with an encoder and gin's c.JSON does not.
func TestAccountsListEnvelope(t *testing.T) {
	store := &mockAccountStore{accounts: []pwdless.Account{{ID: 7, Email: "a@b.co", Name: "A", Active: true}}}
	ts := adminServer(t, store)
	token := adminToken(t, "admin")

	for _, path := range []string{"/admin/accounts", "/admin/accounts/"} {
		resp, body := request(t, ts, http.MethodGet, path, token, "", "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status: want 200, got %d (%s)", path, resp.StatusCode, body)
		}
		if got := resp.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("%s: content type: want application/json, got %q", path, got)
		}
		if !strings.HasPrefix(body, "{\"accounts\":[{") || !strings.HasSuffix(body, "\"count\":1}\n") {
			t.Errorf("%s: body: want an accounts/count envelope ending in a newline, got %q", path, body)
		}
	}
}

// TestAccountsListRenderError pins the upstream inconsistency where list reports store failures
// through ErrRender, whose StatusText in this package is the copy-pasted "Error rendering response."
func TestAccountsListRenderError(t *testing.T) {
	ts := adminServer(t, &mockAccountStore{listErr: errors.New("boom")})

	resp, body := request(t, ts, http.MethodGet, "/admin/accounts", adminToken(t, "admin"), "", "")

	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("status: want 422, got %d", resp.StatusCode)
	}
	if want := "{\"status\":\"Error rendering response.\",\"error\":\"boom\"}\n"; body != want {
		t.Errorf("body: want %q, got %q", want, body)
	}
}

// TestAccountByIDRoutes pins the path parameter seam: chi read {accountID}, gin reads :accountID,
// and a mismatch would surface only as a 400 from the Atoi in accountCtx.
func TestAccountByIDRoutes(t *testing.T) {
	store := &mockAccountStore{accounts: []pwdless.Account{{ID: 7, Email: "a@b.co", Name: "A", Active: true}}}
	ts := adminServer(t, store)
	token := adminToken(t, "admin")

	for _, path := range []string{"/admin/accounts/7", "/admin/accounts/7/"} {
		resp, body := request(t, ts, http.MethodGet, path, token, "", "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status: want 200, got %d (%s)", path, resp.StatusCode, body)
		}
		if !strings.Contains(body, "\"id\":7") {
			t.Errorf("%s: body: want the account with id 7, got %q", path, body)
		}
	}

	resp, body := request(t, ts, http.MethodGet, "/admin/accounts/not-a-number", token, "", "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status: want 400, got %d", resp.StatusCode)
	}
	if want := "{\"status\":\"Bad Request\"}\n"; body != want {
		t.Errorf("body: want %q, got %q", want, body)
	}

	resp, body = request(t, ts, http.MethodGet, "/admin/accounts/99", token, "", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status: want 404, got %d", resp.StatusCode)
	}
	if want := "{\"status\":\"Not Found\"}\n"; body != want {
		t.Errorf("body: want %q, got %q", want, body)
	}
}

// TestAccountDeleteRespondsEmptyObject pins that http.NoBody still marshals to "{}" plus a
// newline. gin's c.JSON on http.NoBody would emit the same object without the newline.
func TestAccountDeleteRespondsEmptyObject(t *testing.T) {
	store := &mockAccountStore{accounts: []pwdless.Account{{ID: 7, Email: "a@b.co", Name: "A"}}}
	ts := adminServer(t, store)

	resp, body := request(t, ts, http.MethodDelete, "/admin/accounts/7", adminToken(t, "admin"), "", "")

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: want 200, got %d", resp.StatusCode)
	}
	if body != "{}\n" {
		t.Errorf("body: want %q, got %q", "{}\n", body)
	}
}

// TestAccountCreateIgnoresContentType pins that the body is decoded as JSON whatever the
// Content-Type says. The source router forced the JSON content type into the request context and
// the decoder consulted that before the header, so dispatching on the header would reject requests
// the source accepted.
func TestAccountCreateIgnoresContentType(t *testing.T) {
	ts := adminServer(t, &mockAccountStore{})

	for _, contentType := range []string{"", "text/plain", "application/xml", "application/x-www-form-urlencoded"} {
		resp, body := request(t, ts, http.MethodPost, "/admin/accounts", adminToken(t, "admin"),
			contentType, `{"email":"ct@example.com","name":"CT","active":true}`)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("content type %q: status: want 200, got %d (%s)", contentType, resp.StatusCode, body)
		}
		if !strings.Contains(body, `"email":"ct@example.com"`) {
			t.Errorf("content type %q: want the decoded account echoed back, got %q", contentType, body)
		}
	}
}

// TestAccountCreateRejectsMalformedJSON pins the decoder error surfacing in the envelope.
func TestAccountCreateRejectsMalformedJSON(t *testing.T) {
	ts := adminServer(t, &mockAccountStore{})

	resp, body := request(t, ts, http.MethodPost, "/admin/accounts", adminToken(t, "admin"),
		"application/json", "{not json")

	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("status: want 422, got %d", resp.StatusCode)
	}
	if !strings.HasPrefix(body, `{"status":"Unprocessable Entity","error":"invalid character`) {
		t.Errorf("body: want a decoder error envelope, got %q", body)
	}
	if !strings.HasSuffix(body, "}\n") {
		t.Errorf("body: want a trailing newline, got %q", body)
	}
}

// TestAccountCreateValidationEnvelope pins the third error constructor, whose payload carries
// the nested "errors" object produced by ozzo validation.
func TestAccountCreateValidationEnvelope(t *testing.T) {
	verrs := validation.Errors{"email": errors.New("cannot be blank")}
	ts := adminServer(t, &mockAccountStore{createErr: verrs})

	resp, body := request(t, ts, http.MethodPost, "/admin/accounts", adminToken(t, "admin"),
		"application/json", `{"email":"","name":"A"}`)

	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("status: want 422, got %d", resp.StatusCode)
	}
	want := "{\"status\":\"Unprocessable Entity\",\"error\":\"account validation error\",\"errors\":{\"email\":\"cannot be blank\"}}\n"
	if body != want {
		t.Errorf("body: want %q, got %q", want, body)
	}
}

// TestAccountCreateAcceptsJSON pins the happy path through the JSON branch of the decoder.
func TestAccountCreateAcceptsJSON(t *testing.T) {
	ts := adminServer(t, &mockAccountStore{})

	resp, body := request(t, ts, http.MethodPost, "/admin/accounts", adminToken(t, "admin"),
		"application/json", `{"email":"new@example.com","name":"New","active":true}`)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: want 200, got %d (%s)", resp.StatusCode, body)
	}
	if !strings.Contains(body, "\"email\":\"new@example.com\"") {
		t.Errorf("body: want the decoded account echoed back, got %q", body)
	}
}
