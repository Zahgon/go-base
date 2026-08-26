package app

import (
	"context"
	"errors"

	"github.com/dhax/go-base/auth/jwt"
	"github.com/dhax/go-base/models"
	"github.com/gin-gonic/gin"
	validation "github.com/go-ozzo/ozzo-validation"
)

// The list of error types returned from account resource.
var (
	ErrProfileValidation = errors.New("profile validation error")
)

// ProfileStore defines database operations for a profile.
type ProfileStore interface {
	Get(accountID int) (*models.Profile, error)
	Update(p *models.Profile) error
}

// ProfileResource implements profile management handler.
type ProfileResource struct {
	Store ProfileStore
}

// NewProfileResource creates and returns a profile resource.
func NewProfileResource(store ProfileStore) *ProfileResource {
	return &ProfileResource{
		Store: store,
	}
}

func (rs *ProfileResource) router(r *gin.RouterGroup) {
	r.Use(rs.profileCtx)
	r.GET("", rs.get)
	r.GET("/", rs.get)
	r.PUT("", rs.update)
	r.PUT("/", rs.update)
}

func (rs *ProfileResource) profileCtx(c *gin.Context) {
	claims := jwt.ClaimsFromCtx(c.Request.Context())
	p, err := rs.Store.Get(claims.ID)
	if err != nil {
		log(c.Request).WithField("profileCtx", claims.Sub).Error(err)
		ErrInternalServerError.Render(c)
		return
	}
	ctx := context.WithValue(c.Request.Context(), ctxProfile, p)
	c.Request = c.Request.WithContext(ctx)
	c.Next()
}

type profileRequest struct {
	*models.Profile
	ProtectedID int `json:"id"`
}

func (d *profileRequest) Bind(c *gin.Context) error {
	return nil
}

type profileResponse struct {
	*models.Profile
}

func newProfileResponse(p *models.Profile) *profileResponse {
	return &profileResponse{
		Profile: p,
	}
}

func (rs *ProfileResource) get(c *gin.Context) {
	p := c.Request.Context().Value(ctxProfile).(*models.Profile)
	respond(c, newProfileResponse(p))
}

func (rs *ProfileResource) update(c *gin.Context) {
	p := c.Request.Context().Value(ctxProfile).(*models.Profile)
	data := &profileRequest{Profile: p}
	if err := bind(c, data); err != nil {
		ErrInvalidRequest(err).Render(c)
	}

	if err := rs.Store.Update(p); err != nil {
		switch err := err.(type) {
		case validation.Errors:
			ErrValidation(ErrProfileValidation, err).Render(c)
			return
		}
		ErrRender(err).Render(c)
		return
	}
	respond(c, newProfileResponse(p))
}
