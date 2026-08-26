package app

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	validation "github.com/go-ozzo/ozzo-validation"

	"github.com/dhax/go-base/auth/jwt"
	"github.com/dhax/go-base/auth/pwdless"
)

// The list of error types returned from account resource.
var (
	ErrAccountValidation = errors.New("account validation error")
)

// AccountStore defines database operations for account.
type AccountStore interface {
	Get(id int) (*pwdless.Account, error)
	Update(*pwdless.Account) error
	Delete(*pwdless.Account) error
	UpdateToken(*jwt.Token) error
	DeleteToken(*jwt.Token) error
}

// AccountResource implements account management handler.
type AccountResource struct {
	Store AccountStore
}

// NewAccountResource creates and returns an account resource.
func NewAccountResource(store AccountStore) *AccountResource {
	return &AccountResource{
		Store: store,
	}
}

func (rs *AccountResource) router(r *gin.RouterGroup) {
	r.Use(rs.accountCtx)
	r.GET("", rs.get)
	r.GET("/", rs.get)
	r.PUT("", rs.update)
	r.PUT("/", rs.update)
	r.DELETE("", rs.delete)
	r.DELETE("/", rs.delete)

	token := r.Group("/token/:tokenID")
	token.PUT("", rs.updateToken)
	token.PUT("/", rs.updateToken)
	token.DELETE("", rs.deleteToken)
	token.DELETE("/", rs.deleteToken)
}

func (rs *AccountResource) accountCtx(c *gin.Context) {
	claims := jwt.ClaimsFromCtx(c.Request.Context())
	log(c.Request).WithField("account_id", claims.ID)
	account, err := rs.Store.Get(claims.ID)
	if err != nil {
		// account deleted while access token still valid
		ErrUnauthorized.Render(c)
		return
	}
	ctx := context.WithValue(c.Request.Context(), ctxAccount, account)
	c.Request = c.Request.WithContext(ctx)
	c.Next()
}

type accountRequest struct {
	*pwdless.Account
	// override protected data here, although not really necessary here
	// as we limit updated database columns in store as well
	ProtectedID     int      `json:"id"`
	ProtectedActive bool     `json:"active"`
	ProtectedRoles  []string `json:"roles"`
}

func (d *accountRequest) Bind(c *gin.Context) error {
	// d.ProtectedActive = true
	// d.ProtectedRoles = []string{}
	return nil
}

type accountResponse struct {
	*pwdless.Account
}

func newAccountResponse(a *pwdless.Account) *accountResponse {
	resp := &accountResponse{Account: a}
	return resp
}

func (rs *AccountResource) get(c *gin.Context) {
	acc := c.Request.Context().Value(ctxAccount).(*pwdless.Account)
	respond(c, newAccountResponse(acc))
}

func (rs *AccountResource) update(c *gin.Context) {
	acc := c.Request.Context().Value(ctxAccount).(*pwdless.Account)
	data := &accountRequest{Account: acc}
	if err := bind(c, data); err != nil {
		ErrInvalidRequest(err).Render(c)
		return
	}

	if err := rs.Store.Update(acc); err != nil {
		switch err := err.(type) {
		case validation.Errors:
			ErrValidation(ErrAccountValidation, err).Render(c)
			return
		}
		ErrRender(err).Render(c)
		return
	}

	respond(c, newAccountResponse(acc))
}

func (rs *AccountResource) delete(c *gin.Context) {
	acc := c.Request.Context().Value(ctxAccount).(*pwdless.Account)
	if err := rs.Store.Delete(acc); err != nil {
		ErrRender(err).Render(c)
		return
	}
	respond(c, http.NoBody)
}

type tokenRequest struct {
	Identifier  string
	ProtectedID int `json:"id"`
}

func (d *tokenRequest) Bind(c *gin.Context) error {
	d.Identifier = strings.TrimSpace(d.Identifier)
	return nil
}

func (rs *AccountResource) updateToken(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("tokenID"))
	if err != nil {
		ErrBadRequest.Render(c)
		return
	}
	data := &tokenRequest{}
	if err := bind(c, data); err != nil {
		ErrInvalidRequest(err).Render(c)
		return
	}
	acc := c.Request.Context().Value(ctxAccount).(*pwdless.Account)
	for _, t := range acc.Token {
		if t.ID == id {
			if err := rs.Store.UpdateToken(&jwt.Token{
				ID:         t.ID,
				Identifier: data.Identifier,
			}); err != nil {
				ErrInvalidRequest(err).Render(c)
				return
			}
		}
	}
	respond(c, http.NoBody)
}

func (rs *AccountResource) deleteToken(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("tokenID"))
	if err != nil {
		ErrBadRequest.Render(c)
		return
	}
	acc := c.Request.Context().Value(ctxAccount).(*pwdless.Account)
	for _, t := range acc.Token {
		if t.ID == id {
			rs.Store.DeleteToken(&jwt.Token{ID: t.ID})
		}
	}
	respond(c, http.NoBody)
}
