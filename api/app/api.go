// Package app ties together application resources and handlers.
package app

import (
	"net/http"

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

func log(r *http.Request) logrus.FieldLogger {
	return logging.GetLogEntry(r)
}
