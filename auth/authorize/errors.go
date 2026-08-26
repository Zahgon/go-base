package authorize

import (
	"encoding/json"
	"net/http"

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
	respondJSON(c, e.HTTPStatusCode, e)
}

// The list of default error types without specific error message.
var (
	ErrForbidden = &ErrResponse{
		HTTPStatusCode: http.StatusForbidden,
		StatusText:     http.StatusText(http.StatusForbidden),
	}
)

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
