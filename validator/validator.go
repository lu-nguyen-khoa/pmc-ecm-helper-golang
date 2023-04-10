package validator

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"strings"

	utils "github.com/Pharmacity-JSC/pmc-ecm-utility-golang"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware"
	error_encoder "github.com/lu-nguyen-khoa/pmc-ecm-helper-golang/error"
	"github.com/lu-nguyen-khoa/pmc-ecm-helper-golang/field"
)

type iProtoValidator interface {
	Validate() error
}

type iProtoValidateError interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
}

type IProtoValidatorService interface {
	GetProtoValidatorService()
	GetProtoValidatorHandler() middleware.Middleware
}

type ProtoValidatorService struct {
	logger       *log.Helper
	errorEncoder error_encoder.IErrorEncoderService
}

func NewProtoValidatorService(errEncoder error_encoder.IErrorEncoderService, logger log.Logger) IProtoValidatorService {
	return &ProtoValidatorService{
		errorEncoder: errEncoder,
		logger:       log.NewHelper(logger),
	}
}

func (s *ProtoValidatorService) GetProtoValidatorService() {}

func (s *ProtoValidatorService) GetProtoValidatorHandler() middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (reply interface{}, err error) {
			if v, ok := req.(iProtoValidator); ok {
				if err := v.Validate(); err != nil {
					if validErr, ok := err.(iProtoValidateError); ok {
						return nil, s.errorEncoder.HandlerErrorMessage(ctx, s.handleValidationError(validErr, reflect.TypeOf(req)))
					}

					s.logger.Error(err)
					return nil, s.errorEncoder.HandlerErrorMessage(ctx, field.NewFieldsError("888", http.StatusBadRequest, "UNKNOWN"))
				}
			}
			return handler(ctx, req)
		}
	}
}

func (s *ProtoValidatorService) handleValidationError(err iProtoValidateError, structType reflect.Type) error {
	json := s.findFieldTagJson(err.Field(), structType)
	return field.NewFieldsError("888", http.StatusBadRequest, json)
}

func (s *ProtoValidatorService) findFieldTagJson(prop string, rType reflect.Type) string {
	props := strings.Split(prop, ".")
	rType = s.handleType(rType)

	propName, sliceProp := s.formatProp(props[0])
	field, exists := rType.FieldByName(propName)
	if !exists {
		return s.toSnakeCase(prop)
	}

	return s.recursiveFindField(1, s.formatTag(field.Tag.Get("json")), sliceProp, props, field)
}

func (s *ProtoValidatorService) recursiveFindField(startAt int, beforeTag string, sliceProp string, props []string, field reflect.StructField) string {
	if startAt == len(props) {
		return beforeTag
	}

	fieldType := s.handleType(field.Type)
	propName, sliceProp2 := s.formatProp(props[startAt])
	if field2, exists := fieldType.FieldByName(propName); exists {
		field = field2
		fieldType = s.handleType(field2.Type)
	}

	tagValue := s.formatTag(field.Tag.Get("json"))
	if fieldType.Kind() == reflect.Struct {
		if newField, exists := fieldType.FieldByName(propName); exists {
			field = newField
		}
	} else {
		return fmt.Sprintf("%s%s%s%s", beforeTag, sliceProp, utils.IIF(beforeTag == "", "", "."), tagValue)
	}

	beforeTag = fmt.Sprintf("%s%s%s%s", beforeTag, sliceProp, utils.IIF(beforeTag == "", "", "."), tagValue)
	return s.recursiveFindField(startAt+1, beforeTag, sliceProp2, props, field)
}

func (s *ProtoValidatorService) formatProp(str string) (string, string) {
	if sliceIndex := strings.IndexByte(str, '['); sliceIndex > 0 {
		return string(str[:sliceIndex]), string(str[sliceIndex:])
	}

	return str, ""
}

func (s *ProtoValidatorService) handleType(rType reflect.Type) reflect.Type {
	for utils.ComparableContains(rType.Kind(), reflect.Ptr, reflect.Pointer, reflect.Slice, reflect.Array) {
		rType = rType.Elem()
	}

	return rType
}

func (s *ProtoValidatorService) toSnakeCase(str string) string {
	if len(str) == 0 {
		return str
	}

	compile := regexp.MustCompile("/[A-Z]/g")
	return compile.ReplaceAllString(str, `$1`)
}

func (s *ProtoValidatorService) formatTag(tag string) string {
	return strings.Split(tag, ",")[0]
}
