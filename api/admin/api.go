// Package admin ties together administration resources and handlers.
package admin

import (
	"net/http"

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

func log(r *http.Request) logrus.FieldLogger {
	return logging.GetLogEntry(r)
}
