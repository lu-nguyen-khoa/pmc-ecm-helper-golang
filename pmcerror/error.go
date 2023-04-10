package pmcerror

import "net/http"

type IPMCError interface {
	Error() string
	GetMessage() string
	GetStatus() int
}

type pmcError struct {
	Status  int    `json:"status"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (v *pmcError) Error() string {
	return v.Code
}

func (v *pmcError) GetStatus() int {
	return v.Status
}

func (v *pmcError) GetMessage() string {
	return v.Message
}

func NewError(err string, status int, msg string) IPMCError {
	return &pmcError{Code: err, Status: status, Message: msg}
}

func NewErrorWithoutMsg(err string, status int) IPMCError {
	return &pmcError{Code: err, Status: status}
}

func FromError(err error) IPMCError {
	if httpErr, ok := err.(IPMCError); ok {
		return httpErr
	}

	return NewError(err.Error(), http.StatusInternalServerError, "Internal Server Error!")
}
