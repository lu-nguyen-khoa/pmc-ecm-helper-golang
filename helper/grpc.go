package helper

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/middleware/recovery"
	"github.com/go-kratos/kratos/v2/transport/grpc"
	g_grpc "google.golang.org/grpc"
)

func CreateConnection(endpoint string, timeout time.Duration, middlewares []middleware.Middleware, clientOptions []grpc.ClientOption) *g_grpc.ClientConn {
	if middlewares == nil {
		middlewares = []middleware.Middleware{recovery.Recovery()}
	} else {
		middlewares = append([]middleware.Middleware{recovery.Recovery()}, middlewares...)
	}

	opts := []grpc.ClientOption{
		grpc.WithTimeout(timeout),
		grpc.WithEndpoint(endpoint),
		grpc.WithMiddleware(
			middlewares...,
		),
	}

	if clientOptions != nil {
		opts = append(opts, clientOptions...)
	}

	if strings.Contains(endpoint, ":443") {
		opts = append(opts, grpc.WithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	}

	conn, err := grpc.DialInsecure(
		context.Background(),
		opts...,
	)

	if err != nil {
		fmt.Printf("CreateConnection connection error: %v. EndPoint: %v", err, endpoint)
	}

	return conn
}
