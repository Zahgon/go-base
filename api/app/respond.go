package app

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
)

// requestBinder is implemented by request payloads that post-process themselves
// after decoding.
type requestBinder interface {
	Bind(c *gin.Context) error
}

// bind decodes the request body into v and then runs the payload's own Bind hook.
func bind(c *gin.Context, v requestBinder) error {
	if err := decode(c.Request, v); err != nil {
		return err
	}
	return v.Bind(c)
}

// decode reads the request body as JSON. The source routers installed a middleware that forced the
// JSON content type into the request context, and the decoder consulted that context before the
// Content-Type header, so the header based dispatch to the XML and form decoders never ran.
func decode(r *http.Request, v any) error {
	defer func() { _, _ = io.Copy(io.Discard, r.Body) }()
	return json.NewDecoder(r.Body).Decode(v)
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

// respond writes v as a successful JSON response.
func respond(c *gin.Context, v any) {
	respondJSON(c, http.StatusOK, v)
}
