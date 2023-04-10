package authenticator

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	error_encoder "github.com/lu-nguyen-khoa/pmc-ecm-helper-golang/error"
	pb "github.com/lu-nguyen-khoa/pmc-ecm-helper-golang/internal/authentication/authenticator"
	g_grpc "google.golang.org/grpc"
)

type IAuthenticator interface {
	InternalServiceSignIn(string, string) (ISignInData, error)
	InternalServiceRefreshToken(string, string) (IAccessToken, error)
	LogError(error)
}

type AuthenticatorService struct {
	log    *log.Helper
	client pb.AuthenticatorClient
}

func NewRoleValidatorService(authenConnection *g_grpc.ClientConn, errEncoder error_encoder.IErrorEncoderService, userinfo IUserinfo, publicKey string, accessTimeout time.Duration, refreshTimeout time.Duration, logger log.Logger) IRoleValidatorService {
	log := log.NewHelper(logger)
	var pubKey ed25519.PublicKey
	pubKey, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		log.Error(err)
		panic(err)
	}

	result := &roleManager{
		errorEncoder:   errEncoder,
		publicKey:      pubKey,
		accessTimeout:  accessTimeout,
		refreshTimeout: refreshTimeout,
		userinfo:       userinfo,
	}

	if authenConnection != nil {
		client := pb.NewAuthenticatorClient(authenConnection)
		result.authenticator = &AuthenticatorService{client: client, log: log}
	}

	tokeninfo, err := result.signIn()
	if err != nil {
		log.Error(err)
		panic(err)
	}

	log.Infof("Token ID: %s\nAccess Token: %s\nRefresh Token: %s", tokeninfo.GetTokenId(), tokeninfo.GetAccessToken(), tokeninfo.GetRefreshToken())
	result.serviceTokeninfo = tokeninfo
	result.serviceAccessToken = tokeninfo
	return result
}

func (s *AuthenticatorService) InternalServiceSignIn(username string, password string) (ISignInData, error) {
	pbRequest := &pb.ServiceSignInRequest{Username: username, Password: password}
	reply, err := s.client.ServiceSignIn(context.Background(), pbRequest)
	if err != nil {
		s.log.Error(err)
		return nil, err
	}

	return reply.GetData(), nil
}

func (s *AuthenticatorService) InternalServiceRefreshToken(tokenID string, refreshToken string) (IAccessToken, error) {
	pbRequest := &pb.RefreshTokenRequest{TokenId: tokenID, RefreshToken: refreshToken}
	reply, err := s.client.ServiceRefreshToken(context.Background(), pbRequest)
	if err != nil {
		s.log.Error(err)
		return nil, err
	}

	return reply.GetData(), nil
}

func (s *AuthenticatorService) LogError(err error) {
	s.log.Error(err)
}
