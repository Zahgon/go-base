package jwt

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/dhax/go-base/logging"
)

type ctxKey int

const (
	ctxClaims ctxKey = iota
	ctxRefreshToken
)

// ClaimsFromCtx retrieves the parsed AppClaims from request context.
func ClaimsFromCtx(ctx context.Context) AppClaims {
	return ctx.Value(ctxClaims).(AppClaims)
}

// RefreshTokenFromCtx retrieves the parsed refresh token from context.
func RefreshTokenFromCtx(ctx context.Context) string {
	return ctx.Value(ctxRefreshToken).(string)
}

// Authenticator is a default authentication middleware to enforce access from the
// Verifier middleware request context values. The Authenticator sends a 401 Unauthorized
// response for any unverified tokens and passes the good ones through.
func Authenticator(c *gin.Context) {
	token, claims, err := tokenFromContext(c.Request.Context())

	if err != nil {
		logging.GetLogEntry(c.Request).Warn(err)
		ErrUnauthorized(ErrTokenUnauthorized).Render(c)
		return
	}

	if err := jwt.Validate(token); err != nil {
		ErrUnauthorized(ErrTokenExpired).Render(c)
		return
	}

	// Token is authenticated, parse claims
	var cl AppClaims
	err = cl.ParseClaims(claims)
	if err != nil {
		logging.GetLogEntry(c.Request).Error(err)
		ErrUnauthorized(ErrInvalidAccessToken).Render(c)
		return
	}

	// Set AppClaims on context
	ctx := context.WithValue(c.Request.Context(), ctxClaims, cl)
	c.Request = c.Request.WithContext(ctx)
	c.Next()
}

// AuthenticateRefreshJWT checks validity of refresh tokens and is only used for access token refresh and logout requests. It responds with 401 Unauthorized for invalid or expired refresh tokens.
func AuthenticateRefreshJWT(c *gin.Context) {
	token, claims, err := tokenFromContext(c.Request.Context())
	if err != nil {
		logging.GetLogEntry(c.Request).Warn(err)
		ErrUnauthorized(ErrTokenUnauthorized).Render(c)
		return
	}

	if err := jwt.Validate(token); err != nil {
		ErrUnauthorized(ErrTokenExpired).Render(c)
		return
	}

	// Token is authenticated, parse refresh token string
	var cl RefreshClaims
	err = cl.ParseClaims(claims)
	if err != nil {
		logging.GetLogEntry(c.Request).Error(err)
		ErrUnauthorized(ErrInvalidRefreshToken).Render(c)
		return
	}
	// Set refresh token string on context
	ctx := context.WithValue(c.Request.Context(), ctxRefreshToken, cl.Token)
	c.Request = c.Request.WithContext(ctx)
	c.Next()
}
