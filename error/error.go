package error

import (
	"context"

	pb "github.com/Pharmacity-JSC/pmc-ecm-protobuf-golang/protobuf"
	utils "github.com/Pharmacity-JSC/pmc-ecm-utility-golang"
	"github.com/lu-nguyen-khoa/pmc-ecm-helper-golang/context_handler"
	"github.com/lu-nguyen-khoa/pmc-ecm-helper-golang/field"
	"github.com/lu-nguyen-khoa/pmc-ecm-helper-golang/localize"

	nethttp "net/http"

	kerrors "github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport/http"
)

type IErrorEncoderService interface {
	GetHttpErrorEncoderHandler() http.EncodeErrorFunc
	GetGrpcErrorEncoderHandler() middleware.Middleware
	HandlerErrorGRPC(context.Context, error) *pb.Error
	HandlerErrorMessage(context.Context, error) utils.IPMCError
	GetErrorEncoder()
}

func NewErrorEncoderService(localize localize.ILocalizeService) IErrorEncoderService {
	return &errorEncoder{localize: localize}
}

type errorEncoder struct {
	localize localize.ILocalizeService
}

func (s *errorEncoder) GetErrorEncoder() {}

func (s *errorEncoder) GetHttpErrorEncoderHandler() http.EncodeErrorFunc {
	return s.defaultHttpErrorEncoder
}

func (s *errorEncoder) GetGrpcErrorEncoderHandler() middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (reply interface{}, err error) {
			if err == nil {
				return handler(ctx, req)
			}

			pbError := s.handleErrorMsg(ctx, err)
			return nil, kerrors.New(int(pbError.GetStatus()), pbError.GetCode(), pbError.GetMessage())
		}
	}
}

func (s *errorEncoder) HandlerErrorGRPC(ctx context.Context, err error) *pb.Error {
	if err == nil {
		return nil
	}

	return s.handleErrorMsg(ctx, err)
}

func (s *errorEncoder) HandlerErrorMessage(ctx context.Context, err error) utils.IPMCError {
	if err == nil {
		return nil
	}

	pbError := s.handleErrorMsg(ctx, err)

	return utils.New(pbError.GetCode(), int(pbError.GetStatus()), pbError.GetMessage())
}

func (s *errorEncoder) defaultHttpErrorEncoder(w http.ResponseWriter, r *http.Request, err error) {
	context := r.Context()
	pbError := s.handleErrorMsg(context, err)
	codec, _ := http.CodecForRequest(r, "Accept")
	body, err := codec.Marshal(pbError)
	if err != nil {
		w.WriteHeader(nethttp.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", context_handler.ContentType(codec.Name()))
	w.WriteHeader(int(pbError.GetStatus()))
	_, _ = w.Write(body)
}

func (s *errorEncoder) handleErrorMsg(ctx context.Context, err error) *pb.Error {
	if pmcErr, ok := err.(utils.IPMCError); ok {
		result := &pb.Error{
			Code:    pmcErr.Error(),
			Status:  int32(pmcErr.GetStatus()),
			Message: s.localize.MessageFromContext(ctx, pmcErr.Error()),
		}
		return result
	}

	if fieldError, ok := err.(field.IFieldsError); ok {
		result := &pb.Error{
			Code:    fieldError.Error(),
			Status:  int32(fieldError.Status()),
			Message: s.localize.MessageFromContext(ctx, fieldError.Error(), fieldError.Fields()...),
		}
		return result
	}

	return &pb.Error{
		Code:    err.Error(),
		Status:  nethttp.StatusInternalServerError,
		Message: s.localize.MessageFromContext(ctx, err.Error()),
	}
}
