package admin

import (
	"net/http"

	"github.com/dhax/go-base/render"
	"github.com/gin-gonic/gin"
	validation "github.com/go-ozzo/ozzo-validation"
)

// ErrResponse renderer type for handling all sorts of errors.
type ErrResponse struct {
	Err            error `json:"-"` // low-level runtime error
	HTTPStatusCode int   `json:"-"` // http response status code

	StatusText       string            `json:"status"`           // user-level status message
	AppCode          int64             `json:"code,omitempty"`   // application-specific error code
	ErrorText        string            `json:"error,omitempty"`  // application-level error message, for debugging
	ValidationErrors validation.Errors `json:"errors,omitempty"` // user level model validation errors
}

// Render responds with the application-specific error code and aborts the chain.
func (e *ErrResponse) Render(c *gin.Context) {
	c.Abort()
	render.JSON(c, e.HTTPStatusCode, e)
}

// ErrInvalidRequest returns status 422 Unprocessable Entity including error message.
func ErrInvalidRequest(err error) *ErrResponse {
	return &ErrResponse{
		Err:            err,
		HTTPStatusCode: http.StatusUnprocessableEntity,
		StatusText:     http.StatusText(http.StatusUnprocessableEntity),
		ErrorText:      err.Error(),
	}
}

// ErrRender returns status 422 Unprocessable Entity rendering response error.
func ErrRender(err error) *ErrResponse {
	return &ErrResponse{
		Err:            err,
		HTTPStatusCode: http.StatusUnprocessableEntity,
		StatusText:     "Error rendering response.",
		ErrorText:      err.Error(),
	}
}

// ErrValidation returns status 422 Unprocessable Entity stating validation errors.
func ErrValidation(err error, valErr validation.Errors) *ErrResponse {
	return &ErrResponse{
		Err:              err,
		HTTPStatusCode:   http.StatusUnprocessableEntity,
		StatusText:       http.StatusText(http.StatusUnprocessableEntity),
		ErrorText:        err.Error(),
		ValidationErrors: valErr,
	}
}

var (
	// ErrBadRequest return status 400 Bad Request for malformed request body.
	ErrBadRequest = &ErrResponse{HTTPStatusCode: http.StatusBadRequest, StatusText: http.StatusText(http.StatusBadRequest)}

	// ErrNotFound returns status 404 Not Found for invalid resource request.
	ErrNotFound = &ErrResponse{HTTPStatusCode: http.StatusNotFound, StatusText: http.StatusText(http.StatusNotFound)}

	// ErrInternalServerError returns status 500 Internal Server Error.
	ErrInternalServerError = &ErrResponse{HTTPStatusCode: http.StatusInternalServerError, StatusText: http.StatusText(http.StatusInternalServerError)}
)
