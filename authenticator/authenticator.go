package authenticator

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	pb "github.com/lu-nguyen-khoa/pmc-ecm-helper-golang/internal/authentication/authenticator"
	g_grpc "google.golang.org/grpc"
)

type AuthenticatorService struct {
	log    *log.Helper
	client pb.AuthenticatorClient
}

func NewRoleValidatorHandler(userinfo IUserinfo, publicKey string, accessTimeout time.Duration, refreshTimeout time.Duration, authConnection *g_grpc.ClientConn, logger log.Logger) IRoleValidatorHandler {
	log := log.NewHelper(logger)
	var pubKey ed25519.PublicKey
	pubKey, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		log.Error(err)
		panic(err)
	}

	client := pb.NewAuthenticatorClient(authConnection)
	service := &AuthenticatorService{client: client, log: log}
	result := &roleManager{
		publicKey:      pubKey,
		accessTimeout:  accessTimeout,
		refreshTimeout: refreshTimeout,
		userinfo:       userinfo,
		authenticator:  service,
	}

	tokeninfo, err := result.signIn()
	if err != nil {
		log.Error(err)
		panic(err)
	}

	result.tokeninfo = tokeninfo
	result.accessToken = tokeninfo
	return result
}

func NewAuthenticatorService(client pb.AuthenticatorClient, logger log.Logger) *AuthenticatorService {
	return &AuthenticatorService{
		client: client,
		log:    log.NewHelper(logger),
	}
}

func (s *AuthenticatorService) ServiceSignIn(username string, password string) (ISignInData, error) {
	pbRequest := &pb.ServiceSignInRequest{Username: username, Password: password}
	reply, err := s.client.ServiceSignIn(context.Background(), pbRequest)
	if err != nil {
		s.log.Error(err)
		return nil, err
	}

	return reply.GetData(), nil
}

func (s *AuthenticatorService) ServiceRefreshToken(tokenID string, refreshToken string) (IAccessToken, error) {
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
