package service

import (
	"context"
	"encoding/base64"
	"github.com/omecodes/common/errors"
	"github.com/omecodes/common/grpcx"
	"github.com/omecodes/common/utils/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"strings"
)

type defaultInterceptor struct {
	interceptors []Interceptor
}

func (interceptor *defaultInterceptor) InterceptUnary(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	var err error

	for _, i := range interceptor.interceptors {
		ctx, err = i.Intercept(ctx)
		if err != nil {
			return nil, err
		}
	}

	rsp, err := handler(ctx, req)
	return rsp, err
}

func (interceptor *defaultInterceptor) InterceptStream(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	var err error
	ctx := ss.Context()

	for _, i := range interceptor.interceptors {
		ctx, err = i.Intercept(ctx)
	}

	ss = grpcx.WrapServerStream(ctx, ss)

	err = handler(srv, ss)
	return err
}

func Default(i ...Interceptor) *defaultInterceptor {
	return &defaultInterceptor{interceptors: i}
}

type Interceptor interface {
	Intercept(ctx context.Context) (context.Context, error)
}

type JwtVerifyFunc func(ctx context.Context, jwt string) (context.Context, error)

type idToken struct {
	verifyFunc JwtVerifyFunc
}

func (j *idToken) Intercept(ctx context.Context) (context.Context, error) {
	var err error

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx, nil
	}

	meta := md.Get("authorization")
	if len(meta) != 0 {
		authorization := meta[0]
		head := authorization[:7]
		if strings.HasPrefix(strings.ToLower(head), "bearer ") {
			ctx, err = j.verifyFunc(ctx, authorization[7:])
			if err != nil {
				log.Error("failed to verify token", log.Err(err))
				err = errors.Unauthorized
			}
		}
	}

	return ctx, err
}

func Jwt(verifyFunc JwtVerifyFunc) *idToken {
	return &idToken{
		verifyFunc: verifyFunc,
	}
}

type proxyBasic struct{}

func (b *proxyBasic) Intercept(ctx context.Context) (context.Context, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errors.Forbidden
	}

	meta := md.Get("proxy-authorization")
	if len(meta) == 0 {
		return ctx, nil
	}

	authorization := meta[0]
	if strings.HasPrefix(authorization, "Basic ") {
		authorization = strings.TrimPrefix(authorization, "Basic ")

		decodedBytes, err := base64.StdEncoding.DecodeString(authorization)
		if err != nil {
			return nil, errors.Forbidden
		}

		var key string
		var secret string

		splits := strings.Split(string(decodedBytes), ":")
		key = splits[0]
		if len(splits) > 1 {
			secret = splits[1]
		}

		ctx = grpcx.ContextWithProxyCredentials(ctx, &grpcx.ProxyCredentials{
			Key:    key,
			Secret: secret,
		})
	}
	return ctx, nil
}

func ProxyBasic() *proxyBasic {
	return &proxyBasic{}
}