package authorize

import (
	"net/http"

	"github.com/dhax/go-base/render"
	"github.com/gin-gonic/gin"
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
	render.JSON(c, e.HTTPStatusCode, e)
}

// The list of default error types without specific error message.
var (
	ErrForbidden = &ErrResponse{
		HTTPStatusCode: http.StatusForbidden,
		StatusText:     http.StatusText(http.StatusForbidden),
	}
)
