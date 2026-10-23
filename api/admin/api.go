// Package admin ties together administration resources and handlers.
package admin

import (
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/uptrace/bun"

	"github.com/gin-gonic/gin"

	"github.com/dhax/go-base/auth/authorize"
	"github.com/dhax/go-base/database"
	"github.com/dhax/go-base/logging"
)

// RoleAdmin is the role required to reach any admin route, including the ones that match
// no handler: the guard runs before the not found response.
const (
	RoleAdmin = "admin"
)

type ctxKey int

const (
	ctxAccount ctxKey = iota
)

// API provides admin application resources and handlers.
type API struct {
	Accounts *AccountResource
}

// NewAPI configures and returns admin application API.
func NewAPI(db *bun.DB) (*API, error) {
	accountStore := database.NewAdmAccountStore(db)
	accounts := NewAccountResource(accountStore)

	api := &API{
		Accounts: accounts,
	}
	return api, nil
}

// Router registers admin application routes on the given router group.
func (a *API) Router(r *gin.RouterGroup) {
	r.Use(authorize.RequiresRole(RoleAdmin))

	index := func(c *gin.Context) {
		c.Writer.Write([]byte("Hello Admin"))
		log(c.Request).Debug("admin access")
	}
	r.GET("", index)
	r.GET("/", index)

	a.Accounts.router(r.Group("/accounts"))
}

// Scope returns the middleware the source router ran for a request below the admin mount point, given the
// request path relative to that mount point. The mounted routers ran their middleware before deciding on a
// not found or method not allowed answer, so the engine replays this chain for requests that match no route.
func (a *API) Scope(path string) []gin.HandlerFunc {
	chain := []gin.HandlerFunc{authorize.RequiresRole(RoleAdmin)}
	if id, ok := pathParam(path, "/accounts/"); ok {
		chain = append(chain, withParam("accountID", id, a.Accounts.accountCtx))
	}
	return chain
}

// pathParam returns the path segment that follows prefix, which a parameterised mount would capture. The
// segment may be empty when a further slash follows it, as in "/accounts//".
func pathParam(path, prefix string) (string, bool) {
	if !strings.HasPrefix(path, prefix) {
		return "", false
	}
	segment, _, nested := strings.Cut(strings.TrimPrefix(path, prefix), "/")
	return segment, segment != "" || nested
}

// withParam runs h with a route parameter set, as a matched parameterised route would have it.
func withParam(key, value string, h gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Params = append(c.Params, gin.Param{Key: key, Value: value})
		h(c)
	}
}

func log(r *http.Request) logrus.FieldLogger {
	return logging.GetLogEntry(r)
}
