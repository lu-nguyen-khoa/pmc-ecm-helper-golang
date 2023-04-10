package authenticator

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	utils "github.com/Pharmacity-JSC/pmc-ecm-utility-golang"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport"
	jwt "github.com/golang-jwt/jwt/v4"
	error_encoder "github.com/lu-nguyen-khoa/pmc-ecm-helper-golang/error"
	"github.com/lu-nguyen-khoa/pmc-ecm-helper-golang/field"
	"github.com/mitchellh/mapstructure"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ISignInData interface {
	GetAccessToken() string
	GetTokenId() string
	GetRefreshToken() string
}

type IAccessToken interface {
	GetAccessToken() string
}

type IUserinfo interface {
	GetUsername() string
	GetPassword() string
}

type IRoleValidatorService interface {
	GetRoleValidatorService()
	SetAuthenticator(IAuthenticator)
	RefreshToken() error
	GetRoleValidatorHandler() middleware.Middleware
	GetTokenExpiredHandler() middleware.Middleware
}

type roleManager struct {
	errorEncoder       error_encoder.IErrorEncoderService
	publicKey          ed25519.PublicKey
	accessTimeout      time.Duration
	refreshTimeout     time.Duration
	userinfo           IUserinfo
	serviceTokeninfo   ISignInData
	serviceAccessToken IAccessToken
	authenticator      IAuthenticator
}

func (m *roleManager) GetRoleValidatorService() {}

func (m *roleManager) SetAuthenticator(authenService IAuthenticator) {
	m.authenticator = authenService
}

func (m *roleManager) RefreshToken() error {
	reply, err := m.authenticator.InternalServiceRefreshToken(m.serviceTokeninfo.GetTokenId(), m.serviceTokeninfo.GetRefreshToken())
	if err != nil {
		m.authenticator.LogError(err)
		return err
	}

	m.serviceAccessToken = reply
	return nil
}

func (m *roleManager) GetRoleValidatorHandler() middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (reply interface{}, err error) {
			trans, ok := transport.FromServerContext(ctx)
			if !ok {
				return handler(ctx, req)
			}

			rType := reflect.TypeOf(req)
			if utils.ComparableContains(rType.Kind(), reflect.Pointer) {
				rType = rType.Elem()
			}

			config, exists := rType.FieldByName("RoleConfig")
			if !exists {
				return handler(ctx, req)
			}

			moduleID, err := strconv.ParseInt(config.Tag.Get("module_id"), 10, 64)
			if err != nil {
				m.authenticator.LogError(err)
				return nil, field.NewFieldsError("430", http.StatusNotImplemented)
			}

			methodIndex, err := strconv.ParseInt(config.Tag.Get("method_id"), 10, 64)
			if err != nil {
				m.authenticator.LogError(err)
				return nil, field.NewFieldsError("431", http.StatusNotImplemented)
			}

			token := m.getToken(trans.RequestHeader())
			if err := m.validateRoles(token, moduleID, methodIndex); err != nil {
				m.authenticator.LogError(err)
				return nil, err
			}

			return handler(ctx, req)
		}
	}
}

func (m *roleManager) GetTokenExpiredHandler() middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (reply interface{}, err error) {
			trans, ok := transport.FromClientContext(ctx)
			if !ok {
				return handler(ctx, req)
			}

			trans.RequestHeader().Set("Authorization", fmt.Sprintf("Bearer %s", m.serviceAccessToken.GetAccessToken()))
			result, err := handler(ctx, req)
			if err == nil {
				return result, err
			}

			if status, ok := status.FromError(err); ok {
				if status.Code() == codes.Unauthenticated {
					if errRefresh := m.RefreshToken(); errRefresh == nil {
						return handler(ctx, req)
					}
				}
			}

			if errPmc, ok := err.(utils.IPMCError); ok {
				if errPmc.GetStatus() == http.StatusUnauthorized {
					if errRefresh := m.RefreshToken(); errRefresh == nil {
						return handler(ctx, req)
					}
				}
			}

			if errField, ok := err.(field.IFieldsError); ok {
				if errField.Status() == http.StatusUnauthorized {
					if errRefresh := m.RefreshToken(); errRefresh == nil {
						return handler(ctx, req)
					}
				}
			}

			if err != nil && err.Error() == "401" {
				if errRefresh := m.RefreshToken(); errRefresh == nil {
					return handler(ctx, req)
				}
			}

			return result, err
		}
	}
}

func (m *roleManager) validateRoles(token string, moduleID int64, methodID int64) error {
	claims, err := m.validateTokenClaim(token, m.publicKey, m.accessTimeout)
	if err != nil {
		m.authenticator.LogError(err)
		return err
	}

	if !m.hasRole(moduleID, methodID, claims.GetRoles()) {
		return field.NewFieldsError("403", http.StatusForbidden)
	}

	return nil
}

func (m *roleManager) hasRole(roleID int64, index int64, roles map[int64]string) bool {
	if roles == nil {
		return false
	}

	role, exists := roles[roleID]
	if !exists {
		return false
	}

	if len(role) < 1 {
		return false
	}

	if role[0] == '1' {
		return true
	}

	if len(role) <= int(index) {
		return false
	}

	return role[index] == '1'
}

func (m *roleManager) signIn() (ISignInData, error) {
	reply, err := m.authenticator.InternalServiceSignIn(m.userinfo.GetUsername(), m.userinfo.GetPassword())
	if err != nil {
		m.authenticator.LogError(err)
		panic(err)
	}

	return reply, nil
}

func (m *roleManager) getToken(header transport.Header) string {
	token := header.Get("Authorization")
	fields := strings.Fields(token)

	if len(fields) != 0 && fields[0] == "Bearer" {
		token = fields[1]
	}

	return token
}

func (m *roleManager) validateTokenClaim(token string, secret ed25519.PublicKey, ttl time.Duration) (utils.IClaims, error) {
	jwtClaims, err := m.validateToken(token, secret, ttl)
	if err != nil {
		return nil, err
	}

	return m.getClaimsFromJwt(jwtClaims)
}

func (m *roleManager) validateToken(token string, secret ed25519.PublicKey, ttl time.Duration) (*jwt.MapClaims, error) {
	parser := jwt.Parser{
		SkipClaimsValidation: true,
	}

	parseHandle := func(token *jwt.Token) (interface{}, error) {
		return secret, nil
	}

	jwtToken, err := parser.Parse(token, parseHandle)
	if err != nil {
		log.Println(err.Error())
		return nil, field.NewFieldsError("402", http.StatusUnauthorized)
	}

	claims, ok := jwtToken.Claims.(jwt.MapClaims)
	if !ok || !jwtToken.Valid {
		return nil, field.NewFieldsError("403", http.StatusUnauthorized)
	}

	createdAt, ok := claims["crat"].(float64)
	if !ok {
		return nil, field.NewFieldsError("404", http.StatusUnauthorized)
	}

	if int64(createdAt+ttl.Seconds()) < time.Now().Unix() {
		return nil, field.NewFieldsError("401", http.StatusUnauthorized)
	}
	return &claims, nil
}

func (m *roleManager) getClaimsFromJwt(claims *jwt.MapClaims) (utils.IClaims, error) {
	result := &utils.Claims{}
	userClaims := (*claims)["user"]
	if err := mapstructure.WeakDecode(userClaims, &result); err != nil {
		log.Println(err.Error())
		return nil, field.NewFieldsError("000", http.StatusInternalServerError)
	}

	return result, nil
}
