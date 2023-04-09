package authenticator

import (
	"context"
	"crypto/ed25519"
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
	"github.com/lu-nguyen-khoa/pmc-ecm-helper-golang/field"
	"github.com/mitchellh/mapstructure"
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

type IRoleValidatorService interface {
	GetRoleValidatorService()
	RefreshToken() error
	GetRoleValidatorHandler() middleware.Middleware
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

func (m *roleManager) GetRoleValidatorService() {}

func (m *roleManager) RefreshToken() error {
	reply, err := m.authenticator.ServiceRefreshToken(m.tokeninfo.GetTokenId(), m.tokeninfo.GetRefreshToken())
	if err != nil {
		m.authenticator.LogError(err)
		return err
	}

	m.accessToken = reply
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

			methodID, err := strconv.ParseInt(config.Tag.Get("method_id"), 10, 64)
			if err != nil {
				m.authenticator.LogError(err)
				return nil, field.NewFieldsError("000", http.StatusForbidden)
			}

			moduleID, err := strconv.ParseInt(config.Tag.Get("module_id"), 10, 64)
			if err != nil {
				m.authenticator.LogError(err)
				return nil, field.NewFieldsError("000", http.StatusForbidden)
			}

			token := m.getToken(trans.RequestHeader())
			if err := m.validateRoles(token, moduleID, methodID); err != nil {
				m.authenticator.LogError(err)
				return nil, field.NewFieldsError("403", http.StatusForbidden)
			}

			return handler(ctx, req)
		}
	}
}

func (m *roleManager) validateRoles(token string, moduleID int64, methodID int64) error {
	claims, err := m.ValidateTokenClaim(token, m.publicKey, m.accessTimeout)
	if err != nil && err.Error() == "404" {
		err = m.RefreshToken()
	}

	if err != nil {
		m.authenticator.LogError(err)
		return field.NewFieldsError("401", http.StatusUnauthorized)
	}

	if !m.hasRole(moduleID, methodID, claims.GetRoles()) {
		return field.NewFieldsError("403", http.StatusUnauthorized)
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

func (m *roleManager) getToken(header transport.Header) string {
	token := header.Get("Authorization")
	fields := strings.Fields(token)

	if len(fields) != 0 && fields[0] == "Bearer" {
		token = fields[1]
	}

	return token
}

func (m *roleManager) ValidateTokenClaim(token string, secret ed25519.PublicKey, ttl time.Duration) (utils.IClaims, error) {
	jwtClaims, err := m.ValidateToken(token, secret, ttl)
	if err != nil {
		return nil, err
	}

	return m.GetClaimsFromJwt(jwtClaims)
}

func (m *roleManager) ValidateToken(token string, secret ed25519.PublicKey, ttl time.Duration) (*jwt.MapClaims, error) {
	parser := jwt.Parser{
		SkipClaimsValidation: true,
	}

	parseHandle := func(token *jwt.Token) (interface{}, error) {
		return secret, nil
	}

	jwtToken, err := parser.Parse(token, parseHandle)
	if err != nil {
		log.Println(err.Error())
		return nil, field.NewFieldsError("401", http.StatusUnauthorized)
	}

	claims, ok := jwtToken.Claims.(jwt.MapClaims)
	if !ok || !jwtToken.Valid {
		return nil, field.NewFieldsError("402", http.StatusUnauthorized)
	}

	createdAt, ok := claims["crat"].(float64)
	if !ok {
		return nil, field.NewFieldsError("403", http.StatusUnauthorized)
	}

	createdAt = createdAt + float64(ttl.Milliseconds())
	now := float64(time.Now().Unix())
	if createdAt < now {
		return nil, field.NewFieldsError("404", http.StatusUnauthorized)
	}
	return &claims, err
}

func (m *roleManager) GetClaimsFromJwt(claims *jwt.MapClaims) (utils.IClaims, error) {
	result := &utils.Claims{}
	userClaims := (*claims)["user"]
	if err := mapstructure.WeakDecode(userClaims, &result); err != nil {
		log.Println(err.Error())
		return nil, field.NewFieldsError("405", http.StatusUnauthorized)
	}

	return result, nil
}
