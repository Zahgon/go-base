// Package app ties together application resources and handlers.
package app

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/uptrace/bun"

	"github.com/dhax/go-base/database"
	"github.com/dhax/go-base/logging"
)

type ctxKey int

const (
	ctxAccount ctxKey = iota
	ctxProfile
)

// API provides application resources and handlers.
type API struct {
	Account *AccountResource
	Profile *ProfileResource
}

// NewAPI configures and returns application API.
func NewAPI(db *bun.DB) (*API, error) {
	accountStore := database.NewAccountStore(db)
	account := NewAccountResource(accountStore)

	profileStore := database.NewProfileStore(db)
	profile := NewProfileResource(profileStore)

	api := &API{
		Account: account,
		Profile: profile,
	}
	return api, nil
}

// Router registers application routes on the given router group.
func (a *API) Router(r *gin.RouterGroup) {
	a.Account.router(r.Group("/account"))
	a.Profile.router(r.Group("/profile"))
}

// Scope returns the middleware the source router ran for a request below the application mount point, given
// the request path relative to that mount point. The mounted routers ran their middleware before deciding on a
// not found or method not allowed answer, so the engine replays this chain for requests that match no route.
func (a *API) Scope(path string) []gin.HandlerFunc {
	switch {
	case below(path, "/account"):
		return []gin.HandlerFunc{a.Account.accountCtx}
	case below(path, "/profile"):
		return []gin.HandlerFunc{a.Profile.profileCtx}
	}
	return nil
}

// below reports whether path equals prefix or is nested below it.
func below(path, prefix string) bool {
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

func log(r *http.Request) logrus.FieldLogger {
	return logging.GetLogEntry(r)
}
