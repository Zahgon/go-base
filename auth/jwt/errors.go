package jwt

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

// The list of jwt token errors presented to the end user.
var (
	ErrTokenUnauthorized   = errors.New("token unauthorized")
	ErrTokenExpired        = errors.New("token expired")
	ErrInvalidAccessToken  = errors.New("invalid access token")
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	ErrWeakSecret          = errors.New("JWT secret uses a known default value — set AUTH_JWT_SECRET: openssl rand -base64 64")
	ErrSecretTooShort      = errors.New("JWT secret is too short — must be at least 32 characters")
)

// ErrResponse renderer type for handling all sorts of errors.
type ErrResponse struct {
	Err            error `json:"-"` // low-level runtime error
	HTTPStatusCode int   `json:"-"` // http response status code

	StatusText string `json:"status"`          // user-level status message
	AppCode    int64  `json:"code,omitempty"`  // application-specific error code
	ErrorText  string `json:"error,omitempty"` // application-level error message, for debugging
}

// Render responds with the application-specific error code and aborts the chain.
func (e *ErrResponse) Render(c *gin.Context) {
	c.Abort()
	respondJSON(c, e.HTTPStatusCode, e)
}

// ErrUnauthorized renders status 401 Unauthorized with custom error message.
func ErrUnauthorized(err error) *ErrResponse {
	return &ErrResponse{
		Err:            err,
		HTTPStatusCode: http.StatusUnauthorized,
		StatusText:     http.StatusText(http.StatusUnauthorized),
		ErrorText:      err.Error(),
	}
}

// respondJSON writes v as a JSON response body terminated by a newline.
func respondJSON(c *gin.Context, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		http.Error(c.Writer, err.Error(), http.StatusInternalServerError)
		return
	}
	c.Header("Content-Type", "application/json")
	c.Status(status)
	_, _ = c.Writer.Write(append(body, '\n'))
}
