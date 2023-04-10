package authenticator

import (
	"context"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/lu-nguyen-khoa/pmc-ecm-helper-golang/authorize"
	pb "github.com/lu-nguyen-khoa/pmc-ecm-helper-golang/internal/authentication/authenticator"
	g_grpc "google.golang.org/grpc"
)

type AuthenticatorService struct {
	log    *log.Helper
	client pb.AuthenticatorClient
}

func NewAuthenticatorService(conn *g_grpc.ClientConn, logger log.Logger) *AuthenticatorService {
	return &AuthenticatorService{
		client: pb.NewAuthenticatorClient(conn),
		log:    log.NewHelper(logger),
	}
}

func (s *AuthenticatorService) InternalServiceSignIn(username string, password string) (authorize.ISignInData, error) {
	pbRequest := &pb.ServiceSignInRequest{Username: username, Password: password}
	reply, err := s.client.ServiceSignIn(context.Background(), pbRequest)
	if err != nil {
		s.log.Error(err)
		return nil, err
	}

	return reply.GetData(), nil
}

func (s *AuthenticatorService) InternalServiceRefreshToken(tokenID string, refreshToken string) (authorize.IAccessToken, error) {
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
