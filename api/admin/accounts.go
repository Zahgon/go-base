package admin

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/dhax/go-base/auth/pwdless"
	"github.com/dhax/go-base/database"
	validation "github.com/go-ozzo/ozzo-validation"

	"github.com/gin-gonic/gin"
)

// The list of error types returned from account resource.
var (
	ErrAccountValidation = errors.New("account validation error")
)

// AccountStore defines database operations for account management.
type AccountStore interface {
	List(*database.AccountFilter) ([]pwdless.Account, int, error)
	Create(*pwdless.Account) error
	Get(id int) (*pwdless.Account, error)
	Update(*pwdless.Account) error
	Delete(*pwdless.Account) error
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
	r.GET("", rs.list)
	r.GET("/", rs.list)
	r.POST("", rs.create)
	r.POST("/", rs.create)

	account := r.Group("/:accountID")
	account.Use(rs.accountCtx)
	account.GET("", rs.get)
	account.GET("/", rs.get)
	account.PUT("", rs.update)
	account.PUT("/", rs.update)
	account.DELETE("", rs.delete)
	account.DELETE("/", rs.delete)
}

func (rs *AccountResource) accountCtx(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("accountID"))
	if err != nil {
		ErrBadRequest.Render(c)
		return
	}
	account, err := rs.Store.Get(id)
	if err != nil {
		ErrNotFound.Render(c)
		return
	}
	ctx := context.WithValue(c.Request.Context(), ctxAccount, account)
	c.Request = c.Request.WithContext(ctx)
	c.Next()
}

type accountRequest struct {
	*pwdless.Account
}

func (d *accountRequest) Bind(c *gin.Context) error {
	return nil
}

type accountResponse struct {
	*pwdless.Account
}

func newAccountResponse(a *pwdless.Account) *accountResponse {
	resp := &accountResponse{Account: a}
	return resp
}

type accountListResponse struct {
	Accounts *[]pwdless.Account `json:"accounts"`
	Count    int                `json:"count"`
}

func newAccountListResponse(a *[]pwdless.Account, count int) *accountListResponse {
	resp := &accountListResponse{
		Accounts: a,
		Count:    count,
	}
	return resp
}

func (rs *AccountResource) list(c *gin.Context) {
	f, err := database.NewAccountFilter(c.Request.URL.Query())
	if err != nil {
		ErrRender(err).Render(c)
		return
	}
	al, count, err := rs.Store.List(f)
	if err != nil {
		ErrRender(err).Render(c)
		return
	}
	respond(c, newAccountListResponse(&al, count))
}

func (rs *AccountResource) create(c *gin.Context) {
	data := &accountRequest{}
	if err := bind(c, data); err != nil {
		ErrInvalidRequest(err).Render(c)
		return
	}

	if err := rs.Store.Create(data.Account); err != nil {
		switch err := err.(type) {
		case validation.Errors:
			ErrValidation(ErrAccountValidation, err).Render(c)
			return
		}
		ErrInvalidRequest(err).Render(c)
		return
	}
	respond(c, newAccountResponse(data.Account))
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
		ErrInvalidRequest(err).Render(c)
		return
	}

	respond(c, newAccountResponse(acc))
}

func (rs *AccountResource) delete(c *gin.Context) {
	acc := c.Request.Context().Value(ctxAccount).(*pwdless.Account)
	if err := rs.Store.Delete(acc); err != nil {
		ErrInvalidRequest(err).Render(c)
		return
	}
	respond(c, http.NoBody)
}
