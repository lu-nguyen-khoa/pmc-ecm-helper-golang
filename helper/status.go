package helper

import (
	"net/http"

	"google.golang.org/grpc/codes"
)

func GRPCToHTTPStatus(grpcStatus codes.Code) int {
	httpStatus, exists := grpcStatusToHTTP[grpcStatus]
	if !exists {
		return http.StatusInternalServerError
	}

	return httpStatus
}

func HTTPToGRPCStatus(httpStatus int) codes.Code {
	grpcStatus, exists := httpStatusToGRPC[httpStatus]
	if !exists {
		return http.StatusInternalServerError
	}

	return grpcStatus
}

var httpStatusToGRPC = map[int]codes.Code{
	http.StatusOK:                      codes.OK,
	http.StatusCreated:                 codes.OK,
	http.StatusAccepted:                codes.OK,
	http.StatusNoContent:               codes.OK,
	http.StatusBadRequest:              codes.InvalidArgument,
	http.StatusUnauthorized:            codes.Unauthenticated,
	http.StatusForbidden:               codes.PermissionDenied,
	http.StatusNotFound:                codes.NotFound,
	http.StatusMethodNotAllowed:        codes.Unimplemented,
	http.StatusNotAcceptable:           codes.Unimplemented,
	http.StatusProxyAuthRequired:       codes.Unimplemented,
	http.StatusRequestTimeout:          codes.DeadlineExceeded,
	http.StatusConflict:                codes.Aborted,
	http.StatusGone:                    codes.NotFound,
	http.StatusLengthRequired:          codes.InvalidArgument,
	http.StatusPreconditionFailed:      codes.FailedPrecondition,
	http.StatusRequestEntityTooLarge:   codes.ResourceExhausted,
	http.StatusRequestURITooLong:       codes.InvalidArgument,
	http.StatusUnsupportedMediaType:    codes.InvalidArgument,
	http.StatusInternalServerError:     codes.Internal,
	http.StatusNotImplemented:          codes.Unimplemented,
	http.StatusServiceUnavailable:      codes.Unavailable,
	http.StatusGatewayTimeout:          codes.DeadlineExceeded,
	http.StatusHTTPVersionNotSupported: codes.Unimplemented,
}

var grpcStatusToHTTP = map[codes.Code]int{
	codes.OK:                 http.StatusOK,
	codes.Canceled:           http.StatusServiceUnavailable,
	codes.Unknown:            http.StatusInternalServerError,
	codes.InvalidArgument:    http.StatusBadRequest,
	codes.DeadlineExceeded:   http.StatusGatewayTimeout,
	codes.NotFound:           http.StatusNotFound,
	codes.AlreadyExists:      http.StatusConflict,
	codes.PermissionDenied:   http.StatusForbidden,
	codes.Unauthenticated:    http.StatusUnauthorized,
	codes.ResourceExhausted:  http.StatusRequestEntityTooLarge,
	codes.FailedPrecondition: http.StatusPreconditionFailed,
	codes.Aborted:            http.StatusConflict,
	codes.OutOfRange:         http.StatusBadRequest,
	codes.Unimplemented:      http.StatusNotImplemented,
	codes.Internal:           http.StatusInternalServerError,
	codes.Unavailable:        http.StatusServiceUnavailable,
	codes.DataLoss:           http.StatusInternalServerError,
}
