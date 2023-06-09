// Code generated by protoc-gen-go-http. DO NOT EDIT.
// versions:
// - protoc-gen-go-http v2.6.1
// - protoc             v3.21.12
// source: api/authenticator/authenticator.proto

package authenticator

import (
	context "context"
	http "github.com/go-kratos/kratos/v2/transport/http"
	binding "github.com/go-kratos/kratos/v2/transport/http/binding"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the kratos package it is being compiled against.
var _ = new(context.Context)
var _ = binding.EncodeURL

const _ = http.SupportPackageIsVersion1

const OperationAuthenticatorServiceRefreshToken = "/pharmacity.authentication.authenticator.Authenticator/ServiceRefreshToken"
const OperationAuthenticatorServiceSignIn = "/pharmacity.authentication.authenticator.Authenticator/ServiceSignIn"
const OperationAuthenticatorUserRefreshToken = "/pharmacity.authentication.authenticator.Authenticator/UserRefreshToken"
const OperationAuthenticatorUserSignIn = "/pharmacity.authentication.authenticator.Authenticator/UserSignIn"

type AuthenticatorHTTPServer interface {
	ServiceRefreshToken(context.Context, *RefreshTokenRequest) (*RefreshTokenReply, error)
	ServiceSignIn(context.Context, *ServiceSignInRequest) (*ServiceSignInReply, error)
	UserRefreshToken(context.Context, *RefreshTokenRequest) (*RefreshTokenReply, error)
	UserSignIn(context.Context, *UserSignInRequest) (*UserSignInReply, error)
}

func RegisterAuthenticatorHTTPServer(s *http.Server, srv AuthenticatorHTTPServer) {
	r := s.Route("/")
	r.POST("/api/authenticator/user/sign-in", _Authenticator_UserSignIn0_HTTP_Handler(srv))
	r.GET("/api/authenticator/user/refresh-token", _Authenticator_UserRefreshToken0_HTTP_Handler(srv))
	r.POST("/api/authenticator/service/sign-in", _Authenticator_ServiceSignIn0_HTTP_Handler(srv))
	r.GET("/api/authenticator/service/refresh-token", _Authenticator_ServiceRefreshToken0_HTTP_Handler(srv))
}

func _Authenticator_UserSignIn0_HTTP_Handler(srv AuthenticatorHTTPServer) func(ctx http.Context) error {
	return func(ctx http.Context) error {
		var in UserSignInRequest
		if err := ctx.Bind(&in); err != nil {
			return err
		}
		http.SetOperation(ctx, OperationAuthenticatorUserSignIn)
		h := ctx.Middleware(func(ctx context.Context, req interface{}) (interface{}, error) {
			return srv.UserSignIn(ctx, req.(*UserSignInRequest))
		})
		out, err := h(ctx, &in)
		if err != nil {
			return err
		}
		reply := out.(*UserSignInReply)
		return ctx.Result(200, reply)
	}
}

func _Authenticator_UserRefreshToken0_HTTP_Handler(srv AuthenticatorHTTPServer) func(ctx http.Context) error {
	return func(ctx http.Context) error {
		var in RefreshTokenRequest
		if err := ctx.BindQuery(&in); err != nil {
			return err
		}
		http.SetOperation(ctx, OperationAuthenticatorUserRefreshToken)
		h := ctx.Middleware(func(ctx context.Context, req interface{}) (interface{}, error) {
			return srv.UserRefreshToken(ctx, req.(*RefreshTokenRequest))
		})
		out, err := h(ctx, &in)
		if err != nil {
			return err
		}
		reply := out.(*RefreshTokenReply)
		return ctx.Result(200, reply)
	}
}

func _Authenticator_ServiceSignIn0_HTTP_Handler(srv AuthenticatorHTTPServer) func(ctx http.Context) error {
	return func(ctx http.Context) error {
		var in ServiceSignInRequest
		if err := ctx.Bind(&in); err != nil {
			return err
		}
		http.SetOperation(ctx, OperationAuthenticatorServiceSignIn)
		h := ctx.Middleware(func(ctx context.Context, req interface{}) (interface{}, error) {
			return srv.ServiceSignIn(ctx, req.(*ServiceSignInRequest))
		})
		out, err := h(ctx, &in)
		if err != nil {
			return err
		}
		reply := out.(*ServiceSignInReply)
		return ctx.Result(200, reply)
	}
}

func _Authenticator_ServiceRefreshToken0_HTTP_Handler(srv AuthenticatorHTTPServer) func(ctx http.Context) error {
	return func(ctx http.Context) error {
		var in RefreshTokenRequest
		if err := ctx.BindQuery(&in); err != nil {
			return err
		}
		http.SetOperation(ctx, OperationAuthenticatorServiceRefreshToken)
		h := ctx.Middleware(func(ctx context.Context, req interface{}) (interface{}, error) {
			return srv.ServiceRefreshToken(ctx, req.(*RefreshTokenRequest))
		})
		out, err := h(ctx, &in)
		if err != nil {
			return err
		}
		reply := out.(*RefreshTokenReply)
		return ctx.Result(200, reply)
	}
}

type AuthenticatorHTTPClient interface {
	ServiceRefreshToken(ctx context.Context, req *RefreshTokenRequest, opts ...http.CallOption) (rsp *RefreshTokenReply, err error)
	ServiceSignIn(ctx context.Context, req *ServiceSignInRequest, opts ...http.CallOption) (rsp *ServiceSignInReply, err error)
	UserRefreshToken(ctx context.Context, req *RefreshTokenRequest, opts ...http.CallOption) (rsp *RefreshTokenReply, err error)
	UserSignIn(ctx context.Context, req *UserSignInRequest, opts ...http.CallOption) (rsp *UserSignInReply, err error)
}

type AuthenticatorHTTPClientImpl struct {
	cc *http.Client
}

func NewAuthenticatorHTTPClient(client *http.Client) AuthenticatorHTTPClient {
	return &AuthenticatorHTTPClientImpl{client}
}

func (c *AuthenticatorHTTPClientImpl) ServiceRefreshToken(ctx context.Context, in *RefreshTokenRequest, opts ...http.CallOption) (*RefreshTokenReply, error) {
	var out RefreshTokenReply
	pattern := "/api/authenticator/service/refresh-token"
	path := binding.EncodeURL(pattern, in, true)
	opts = append(opts, http.Operation(OperationAuthenticatorServiceRefreshToken))
	opts = append(opts, http.PathTemplate(pattern))
	err := c.cc.Invoke(ctx, "GET", path, nil, &out, opts...)
	if err != nil {
		return nil, err
	}
	return &out, err
}

func (c *AuthenticatorHTTPClientImpl) ServiceSignIn(ctx context.Context, in *ServiceSignInRequest, opts ...http.CallOption) (*ServiceSignInReply, error) {
	var out ServiceSignInReply
	pattern := "/api/authenticator/service/sign-in"
	path := binding.EncodeURL(pattern, in, false)
	opts = append(opts, http.Operation(OperationAuthenticatorServiceSignIn))
	opts = append(opts, http.PathTemplate(pattern))
	err := c.cc.Invoke(ctx, "POST", path, in, &out, opts...)
	if err != nil {
		return nil, err
	}
	return &out, err
}

func (c *AuthenticatorHTTPClientImpl) UserRefreshToken(ctx context.Context, in *RefreshTokenRequest, opts ...http.CallOption) (*RefreshTokenReply, error) {
	var out RefreshTokenReply
	pattern := "/api/authenticator/user/refresh-token"
	path := binding.EncodeURL(pattern, in, true)
	opts = append(opts, http.Operation(OperationAuthenticatorUserRefreshToken))
	opts = append(opts, http.PathTemplate(pattern))
	err := c.cc.Invoke(ctx, "GET", path, nil, &out, opts...)
	if err != nil {
		return nil, err
	}
	return &out, err
}

func (c *AuthenticatorHTTPClientImpl) UserSignIn(ctx context.Context, in *UserSignInRequest, opts ...http.CallOption) (*UserSignInReply, error) {
	var out UserSignInReply
	pattern := "/api/authenticator/user/sign-in"
	path := binding.EncodeURL(pattern, in, false)
	opts = append(opts, http.Operation(OperationAuthenticatorUserSignIn))
	opts = append(opts, http.PathTemplate(pattern))
	err := c.cc.Invoke(ctx, "POST", path, in, &out, opts...)
	if err != nil {
		return nil, err
	}
	return &out, err
}
