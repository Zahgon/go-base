// Package pwdless provides JSON Web Token (JWT) authentication and authorization middleware.
// It implements a passwordless authentication flow by sending login tokens vie email which are then exchanged for JWT access and refresh tokens.
package pwdless

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dhax/go-base/auth/jwt"
	"github.com/dhax/go-base/email"
	"github.com/dhax/go-base/logging"
	"github.com/dhax/go-base/render"
	"github.com/gin-gonic/gin"
	validation "github.com/go-ozzo/ozzo-validation"
	"github.com/go-ozzo/ozzo-validation/is"
	"github.com/gofrs/uuid"
	"github.com/mssola/user_agent"
	"github.com/sirupsen/logrus"
)

// AuthStorer defines database operations on accounts and tokens.
type AuthStorer interface {
	GetAccount(id int) (*Account, error)
	GetAccountByEmail(email string) (*Account, error)
	UpdateAccount(a *Account) error

	GetToken(token string) (*jwt.Token, error)
	CreateOrUpdateToken(t *jwt.Token) error
	DeleteToken(t *jwt.Token) error
	PurgeExpiredToken() error
}

// Resource implements passwordless account authentication against a database.
type Resource struct {
	LoginAuth *LoginTokenAuth
	TokenAuth *jwt.TokenAuth
	Store     AuthStorer
	Mailer    email.Mailer
}

// NewResource returns a configured authentication resource.
func NewResource(authStore AuthStorer, mailer email.Mailer) (*Resource, error) {
	loginAuth, err := NewLoginTokenAuth()
	if err != nil {
		return nil, err
	}

	tokenAuth, err := jwt.NewTokenAuth()
	if err != nil {
		return nil, err
	}

	resource := &Resource{
		LoginAuth: loginAuth,
		TokenAuth: tokenAuth,
		Store:     authStore,
		Mailer:    mailer,
	}

	resource.choresTicker()

	return resource, nil
}

// Router provides necessary routes for passwordless authentication flow.
func (rs *Resource) Router(r *gin.RouterGroup) {
	r.POST("/login", rs.login)
	r.POST("/token", rs.token)

	authenticated := r.Group("")
	authenticated.Use(rs.TokenAuth.Verifier())
	authenticated.Use(jwt.AuthenticateRefreshJWT)
	authenticated.POST("/refresh", rs.refresh)
	authenticated.POST("/logout", rs.logout)
}

func log(r *http.Request) logrus.FieldLogger {
	return logging.GetLogEntry(r)
}

type loginRequest struct {
	Email string
}

func (body *loginRequest) Bind(c *gin.Context) error {
	body.Email = strings.TrimSpace(body.Email)
	body.Email = strings.ToLower(body.Email)

	return validation.ValidateStruct(body,
		validation.Field(&body.Email, validation.Required, is.Email),
	)
}

func (rs *Resource) login(c *gin.Context) {
	r := c.Request
	body := &loginRequest{}
	if err := render.Bind(c, body); err != nil {
		log(r).WithField("email", body.Email).Warn(err)
		ErrUnauthorized(ErrInvalidLogin).Render(c)
		return
	}

	acc, err := rs.Store.GetAccountByEmail(body.Email)
	if err != nil {
		log(r).WithField("email", body.Email).Warn(err)
		ErrUnauthorized(ErrUnknownLogin).Render(c)
		return
	}

	if !acc.CanLogin() {
		ErrUnauthorized(ErrLoginDisabled).Render(c)
		return
	}

	lt := rs.LoginAuth.CreateToken(acc.ID)
	tokenURL, _ := url.JoinPath(rs.LoginAuth.loginURL, lt.Token)

	go func() {
		content := ContentLoginToken{
			Email:  acc.Email,
			Name:   acc.Name,
			URL:    tokenURL,
			Token:  lt.Token,
			Expiry: lt.Expiry,
		}

		msg := LoginTokenEmail(acc.Name, acc.Email, content)

		if err := rs.Mailer.Send(msg); err != nil {
			log(r).WithField("module", "email").Error(err)
		}
	}()

	render.Respond(c, http.NoBody)
}

type tokenRequest struct {
	Token string `json:"token"`
}

type tokenResponse struct {
	Access  string `json:"access_token"`
	Refresh string `json:"refresh_token"`
}

func (body *tokenRequest) Bind(c *gin.Context) error {
	body.Token = strings.TrimSpace(body.Token)

	return validation.ValidateStruct(body,
		validation.Field(&body.Token, validation.Required, is.Alphanumeric),
	)
}

func (rs *Resource) token(c *gin.Context) {
	r := c.Request
	body := &tokenRequest{}
	if err := render.Bind(c, body); err != nil {
		log(r).Warn(err)
		ErrUnauthorized(ErrLoginToken).Render(c)
		return
	}

	id, err := rs.LoginAuth.GetAccountID(body.Token)
	if err != nil {
		ErrUnauthorized(ErrLoginToken).Render(c)
		return
	}

	acc, err := rs.Store.GetAccount(id)
	if err != nil {
		// account deleted before login token expired
		ErrUnauthorized(ErrUnknownLogin).Render(c)
		return
	}

	if !acc.CanLogin() {
		ErrUnauthorized(ErrLoginDisabled).Render(c)
		return
	}

	ua := user_agent.New(r.UserAgent())
	browser, _ := ua.Browser()

	token := &jwt.Token{
		Token:      uuid.Must(uuid.NewV4()).String(),
		Expiry:     time.Now().Add(rs.TokenAuth.JwtRefreshExpiry),
		UpdatedAt:  time.Now(),
		AccountID:  acc.ID,
		Mobile:     ua.Mobile(),
		Identifier: fmt.Sprintf("%s on %s", browser, ua.OS()),
	}

	if err := rs.Store.CreateOrUpdateToken(token); err != nil {
		log(r).Error(err)
		ErrInternalServerError.Render(c)
		return
	}

	access, refresh, err := rs.TokenAuth.GenTokenPair(acc.Claims(), token.Claims())
	if err != nil {
		log(r).Error(err)
		ErrInternalServerError.Render(c)
		return
	}

	acc.LastLogin = time.Now()
	if err := rs.Store.UpdateAccount(acc); err != nil {
		log(r).Error(err)
		ErrInternalServerError.Render(c)
		return
	}

	render.Respond(c, &tokenResponse{
		Access:  access,
		Refresh: refresh,
	})
}

func (rs *Resource) refresh(c *gin.Context) {
	r := c.Request
	rt := jwt.RefreshTokenFromCtx(r.Context())

	token, err := rs.Store.GetToken(rt)
	if err != nil {
		ErrUnauthorized(jwt.ErrTokenExpired).Render(c)
		return
	}

	if time.Now().After(token.Expiry) {
		rs.Store.DeleteToken(token)
		ErrUnauthorized(jwt.ErrTokenExpired).Render(c)
		return
	}

	acc, err := rs.Store.GetAccount(token.AccountID)
	if err != nil {
		ErrUnauthorized(ErrUnknownLogin).Render(c)
		return
	}

	if !acc.CanLogin() {
		ErrUnauthorized(ErrLoginDisabled).Render(c)
		return
	}

	token.Token = uuid.Must(uuid.NewV4()).String()
	token.Expiry = time.Now().Add(rs.TokenAuth.JwtRefreshExpiry)
	token.UpdatedAt = time.Now()

	access, refresh, err := rs.TokenAuth.GenTokenPair(acc.Claims(), token.Claims())
	if err != nil {
		log(r).Error(err)
		ErrInternalServerError.Render(c)
		return
	}

	if err := rs.Store.CreateOrUpdateToken(token); err != nil {
		log(r).Error(err)
		ErrInternalServerError.Render(c)
		return
	}

	acc.LastLogin = time.Now()
	if err := rs.Store.UpdateAccount(acc); err != nil {
		log(r).Error(err)
		ErrInternalServerError.Render(c)
		return
	}

	render.Respond(c, &tokenResponse{
		Access:  access,
		Refresh: refresh,
	})
}

func (rs *Resource) logout(c *gin.Context) {
	rt := jwt.RefreshTokenFromCtx(c.Request.Context())
	token, err := rs.Store.GetToken(rt)
	if err != nil {
		ErrUnauthorized(jwt.ErrTokenExpired).Render(c)
		return
	}
	rs.Store.DeleteToken(token)

	render.Respond(c, http.NoBody)
}
