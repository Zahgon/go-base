package authorize

import (
	"slices"

	"github.com/gin-gonic/gin"

	"github.com/dhax/go-base/auth/jwt"
)

// RequiresRole middleware restricts access to accounts having role parameter in their jwt claims.
func RequiresRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims := jwt.ClaimsFromCtx(c.Request.Context())
		if !hasRole(role, claims.Roles) {
			ErrForbidden.Render(c)
		}
	}
}

func hasRole(role string, roles []string) bool {
	return slices.Contains(roles, role)
}
