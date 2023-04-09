package authenticator

import (
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"strconv"
	"time"

	utils "github.com/Pharmacity-JSC/pmc-ecm-utility-golang"
	"github.com/go-kratos/kratos/v2/middleware"
)

type ISignInData interface {
	GetAccessToken() string
	GetTokenId() string
	GetRefreshToken() string
}

type IAccessToken interface {
	GetAccessToken() string
}

type IAuthenticator interface {
	ServiceSignIn(string, string) (ISignInData, error)
	ServiceRefreshToken(string, string) (IAccessToken, error)
	LogError(error)
}

type IUserinfo interface {
	GetUsername() string
	GetPassword() string
}

type IRoleValidatorHandler interface {
	RefreshToken() error
	RoleMiddleware() middleware.Middleware
	RoleValidatorHandler()
}

type roleManager struct {
	publicKey      ed25519.PublicKey
	accessTimeout  time.Duration
	refreshTimeout time.Duration
	userinfo       IUserinfo
	tokeninfo      ISignInData
	accessToken    IAccessToken
	authenticator  IAuthenticator
}

func (m *roleManager) RoleValidatorHandler() {}

func (m *roleManager) RefreshToken() error {
	reply, err := m.authenticator.ServiceRefreshToken(m.tokeninfo.GetTokenId(), m.tokeninfo.GetRefreshToken())
	if err != nil {
		m.authenticator.LogError(err)
		return err
	}

	m.accessToken = reply
	return nil
}

func (m *roleManager) RoleMiddleware() middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (reply interface{}, err error) {
			iToken, ok := req.(utils.IToken)
			if !ok {
				return handler(ctx, req)
			}

			rType := reflect.TypeOf(req)
			if utils.ComparableContains(rType.Kind(), reflect.Pointer) {
				rType = rType.Elem()
			}

			field, exists := rType.FieldByName("Token")
			if !exists {
				return handler(ctx, req)
			}

			methodID, err := strconv.ParseInt(field.Tag.Get("method_id"), 10, 64)
			if err != nil {
				m.authenticator.LogError(err)
				return nil, errors.New("000")
			}

			moduleID, err := strconv.ParseInt(field.Tag.Get("module_id"), 10, 64)
			if err != nil {
				m.authenticator.LogError(err)
				return nil, errors.New("000")
			}

			if err := m.validateRoles(iToken.GetToken(), moduleID, methodID); err != nil {
				m.authenticator.LogError(err)
				return nil, errors.New("403")
			}

			return handler(ctx, req)
		}
	}
}

func (m *roleManager) validateRoles(token string, moduleID int64, methodID int64) error {
	claims, err := utils.ValidateTokenClaim(token, m.publicKey, m.accessTimeout)
	if err != nil && err.Error() == "404" {
		err = m.RefreshToken()
	}

	if err != nil {
		m.authenticator.LogError(err)
		return errors.New("401")
	}

	if !m.hasRole(moduleID, methodID, claims.GetRoles()) {
		return errors.New("402")
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
	reply, err := m.authenticator.ServiceSignIn(m.userinfo.GetUsername(), m.userinfo.GetPassword())
	if err != nil {
		m.authenticator.LogError(err)
		panic(err)
	}

	return reply, nil
}
