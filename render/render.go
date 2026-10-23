// Package render decodes JSON request payloads and writes JSON responses the way every resource of the
// API answers.
package render

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
)

// Binder is implemented by request payloads that post-process themselves after decoding.
type Binder interface {
	Bind(c *gin.Context) error
}

// Bind decodes the request body into v and then runs the payload's own Bind hook.
func Bind(c *gin.Context, v Binder) error {
	if err := Decode(c.Request, v); err != nil {
		return err
	}
	return v.Bind(c)
}

// Decode reads the request body as JSON whatever its Content-Type, as the API always did, and drains
// whatever the decoder left unread.
func Decode(r *http.Request, v any) error {
	defer func() { _, _ = io.Copy(io.Discard, r.Body) }()
	return json.NewDecoder(r.Body).Decode(v)
}

// JSON writes v with the given status as a JSON response body terminated by a newline.
func JSON(c *gin.Context, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		http.Error(c.Writer, err.Error(), http.StatusInternalServerError)
		return
	}
	c.Header("Content-Type", "application/json")
	c.Status(status)
	_, _ = c.Writer.Write(append(body, '\n'))
}

// Respond writes v as a successful JSON response.
func Respond(c *gin.Context, v any) {
	JSON(c, http.StatusOK, v)
}
