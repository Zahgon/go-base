package logging

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync/atomic"

	"github.com/gin-gonic/gin"
)

// RequestIDHeader is the name of the HTTP header carrying a request id supplied
// by an upstream proxy.
var RequestIDHeader = "X-Request-Id"

type requestIDCtxKey struct{}

// RequestIDKey is the request context key holding the request id.
var RequestIDKey = requestIDCtxKey{}

var (
	prefix string
	reqid  uint64
)

func init() {
	hostname, err := os.Hostname()
	if hostname == "" || err != nil {
		hostname = "localhost"
	}
	var buf [12]byte
	var b64 string
	for len(b64) < 10 {
		_, _ = rand.Read(buf[:])
		b64 = base64.StdEncoding.EncodeToString(buf[:])
		b64 = strings.NewReplacer("+", "", "/", "").Replace(b64)
	}
	prefix = fmt.Sprintf("%s/%s", hostname, b64[0:10])
}

// RequestID middleware assigns each request a unique id, reusing the value of
// the X-Request-Id header when the caller supplies one.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.Request.Header.Get(RequestIDHeader)
		if requestID == "" {
			myid := atomic.AddUint64(&reqid, 1)
			requestID = fmt.Sprintf("%s-%06d", prefix, myid)
		}
		ctx := context.WithValue(c.Request.Context(), RequestIDKey, requestID)
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

// GetReqID returns the request id of the given request context, if any.
func GetReqID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if reqID, ok := ctx.Value(RequestIDKey).(string); ok {
		return reqID
	}
	return ""
}

// requestIDFromRequest is a convenience wrapper around GetReqID.
func requestIDFromRequest(r *http.Request) string {
	return GetReqID(r.Context())
}
