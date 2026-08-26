package jwt

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/spf13/viper"
)

// The list of errors reported by the token verifier. They are written to the
// request log only and never rendered to the end user.
var (
	errTokenUnauthorized = errors.New("token is unauthorized")
	errTokenIsExpired    = errors.New("token is expired")
	errNBFInvalid        = errors.New("token nbf validation failed")
	errIATInvalid        = errors.New("token iat validation failed")
	errNoTokenFound      = errors.New("no token found")
)

type verifyCtxKey struct {
	name string
}

func (k *verifyCtxKey) String() string {
	return "jwt context value " + k.name
}

var (
	tokenCtxKey = &verifyCtxKey{"Token"}
	errorCtxKey = &verifyCtxKey{"Error"}
)

// JWTAuth signs, parses and verifies JSON web tokens for a single algorithm and key.
type JWTAuth struct {
	alg      jwa.SignatureAlgorithm
	signKey  any
	verifier jwt.ParseOption
}

// NewJWTAuth returns a JWTAuth for the given signature algorithm and signing key.
func NewJWTAuth(alg string, signKey any) *JWTAuth {
	ja := &JWTAuth{alg: jwa.SignatureAlgorithm(alg), signKey: signKey}
	ja.verifier = jwt.WithKey(ja.alg, signKey)
	return ja
}

// Encode signs the provided claims and returns the token and its serialized form.
func (ja *JWTAuth) Encode(claims map[string]any) (jwt.Token, string, error) {
	t := jwt.New()
	for k, v := range claims {
		if err := t.Set(k, v); err != nil {
			return nil, "", err
		}
	}
	payload, err := jwt.Sign(t, jwt.WithKey(ja.alg, ja.signKey))
	if err != nil {
		return nil, "", err
	}
	return t, string(payload), nil
}

// Decode parses and verifies the signature of tokenString without validating its claims.
func (ja *JWTAuth) Decode(tokenString string) (jwt.Token, error) {
	return jwt.Parse([]byte(tokenString), ja.verifier, jwt.WithValidate(false))
}

// verifyToken decodes and validates a token string.
func verifyToken(ja *JWTAuth, tokenString string) (jwt.Token, error) {
	token, err := ja.Decode(tokenString)
	if err != nil {
		return token, errorReason(err)
	}
	if token == nil {
		return nil, errTokenUnauthorized
	}
	if err := jwt.Validate(token); err != nil {
		return token, errorReason(err)
	}
	return token, nil
}

// verifyRequest extracts a token from the request using findTokenFns in order
// and verifies the first one found.
func verifyRequest(ja *JWTAuth, r *http.Request, findTokenFns ...func(r *http.Request) string) (jwt.Token, error) {
	var tokenString string
	for _, fn := range findTokenFns {
		tokenString = fn(r)
		if tokenString != "" {
			break
		}
	}
	if tokenString == "" {
		return nil, errNoTokenFound
	}
	return verifyToken(ja, tokenString)
}

func errorReason(err error) error {
	switch {
	case errors.Is(err, jwt.ErrTokenExpired()) || errors.Is(err, errTokenIsExpired):
		return errTokenIsExpired
	case errors.Is(err, jwt.ErrInvalidIssuedAt()) || errors.Is(err, errIATInvalid):
		return errIATInvalid
	case errors.Is(err, jwt.ErrTokenNotYetValid()) || errors.Is(err, errNBFInvalid):
		return errNBFInvalid
	default:
		return errTokenUnauthorized
	}
}

// newVerifyContext stores the verified token and verification error on ctx.
func newVerifyContext(ctx context.Context, t jwt.Token, err error) context.Context {
	ctx = context.WithValue(ctx, tokenCtxKey, t)
	ctx = context.WithValue(ctx, errorCtxKey, err)
	return ctx
}

// tokenFromContext returns the token, its claims and the verification error
// recorded by the Verifier middleware.
func tokenFromContext(ctx context.Context) (jwt.Token, map[string]any, error) {
	token, _ := ctx.Value(tokenCtxKey).(jwt.Token)

	var err error
	var claims map[string]any

	if token != nil {
		claims, err = token.AsMap(context.Background())
		if err != nil {
			return token, nil, err
		}
	} else {
		claims = map[string]any{}
	}

	err, _ = ctx.Value(errorCtxKey).(error)

	return token, claims, err
}

// tokenFromHeader returns the bearer token of the Authorization request header.
func tokenFromHeader(r *http.Request) string {
	bearer := r.Header.Get("Authorization")
	if len(bearer) > 7 && strings.ToUpper(bearer[0:6]) == "BEARER" {
		return bearer[7:]
	}
	return ""
}

// tokenFromCookie returns the token stored in the jwt cookie.
func tokenFromCookie(r *http.Request) string {
	cookie, err := r.Cookie("jwt")
	if err != nil {
		return ""
	}
	return cookie.Value
}

// TokenAuth implements JWT authentication flow.
type TokenAuth struct {
	JwtAuth          *JWTAuth
	JwtExpiry        time.Duration
	JwtRefreshExpiry time.Duration
}

// NewTokenAuth configures and returns a JWT authentication instance.
func NewTokenAuth() (*TokenAuth, error) {
	secret := viper.GetString("auth_jwt_secret")
	knownWeakSecrets := map[string]bool{
		"":                true,
		"random":          true,
		"CHANGE-ME":       true,
		"secret":          true,
		"changeme":        true,
		"jwt_secret":      true,
		"your-secret-key": true,
	}
	if knownWeakSecrets[secret] {
		return nil, ErrWeakSecret
	}
	if len(secret) < 32 {
		return nil, ErrSecretTooShort
	}

	a := &TokenAuth{
		JwtAuth:          NewJWTAuth("HS256", []byte(secret)),
		JwtExpiry:        viper.GetDuration("auth_jwt_expiry"),
		JwtRefreshExpiry: viper.GetDuration("auth_jwt_refresh_expiry"),
	}

	return a, nil
}

// Verifier http middleware will verify a jwt string from a http request.
func (a *TokenAuth) Verifier() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := verifyRequest(a.JwtAuth, c.Request, tokenFromHeader, tokenFromCookie)
		c.Request = c.Request.WithContext(newVerifyContext(c.Request.Context(), token, err))
		c.Next()
	}
}

// GenTokenPair returns both an access token and a refresh token.
func (a *TokenAuth) GenTokenPair(accessClaims AppClaims, refreshClaims RefreshClaims) (string, string, error) {
	access, err := a.CreateJWT(accessClaims)
	if err != nil {
		return "", "", err
	}
	refresh, err := a.CreateRefreshJWT(refreshClaims)
	if err != nil {
		return "", "", err
	}
	return access, refresh, nil
}

// CreateJWT returns an access token for provided account claims.
func (a *TokenAuth) CreateJWT(c AppClaims) (string, error) {
	c.IssuedAt = time.Now().Unix()
	c.ExpiresAt = time.Now().Add(a.JwtExpiry).Unix()

	claims, err := ParseStructToMap(c)
	if err != nil {
		return "", err
	}

	_, tokenString, err := a.JwtAuth.Encode(claims)
	return tokenString, err
}

func ParseStructToMap(c any) (map[string]any, error) {
	var claims map[string]any
	inrec, _ := json.Marshal(c)
	err := json.Unmarshal(inrec, &claims)
	if err != nil {
		return nil, err
	}

	return claims, err
}

// CreateRefreshJWT returns a refresh token for provided token Claims.
func (a *TokenAuth) CreateRefreshJWT(c RefreshClaims) (string, error) {
	c.IssuedAt = time.Now().Unix()
	c.ExpiresAt = time.Now().Add(a.JwtRefreshExpiry).Unix()

	claims, err := ParseStructToMap(c)
	if err != nil {
		return "", err
	}

	_, tokenString, err := a.JwtAuth.Encode(claims)
	return tokenString, err
}
