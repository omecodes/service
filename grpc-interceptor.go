package service

import (
	"context"
	"encoding/base64"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/omecodes/common/errors"
	"github.com/omecodes/common/utils/log"
	"github.com/omecodes/libome"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type MergedInterceptor interface {
	InterceptUnary(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error)
	InterceptStream(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error
}

type interceptorChain struct {
	interceptors []Interceptor
}

func (interceptor *interceptorChain) InterceptUnary(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	var err error
	start := time.Now()
	method := path.Base(info.FullMethod)

	for _, i := range interceptor.interceptors {
		ctx, err = i.Intercept(ctx)
		if err != nil {
			return nil, err
		}
	}

	rsp, err := handler(ctx, req)
	if err != nil {
		log.Error(fmt.Sprintf("[gRPC] %s", method), log.Field("request", req), log.Err(err), log.Field("duration", time.Since(start)))

	} else {
		log.Info(fmt.Sprintf("[gRPC] %s", method), log.Field("req", req), log.Field("rsp", rsp), log.Field("duration", time.Since(start)))
	}
	return rsp, err
}

func (interceptor *interceptorChain) InterceptStream(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	var err error
	ctx := ss.Context()

	method := path.Base(info.FullMethod)
	start := time.Now()

	for _, i := range interceptor.interceptors {
		ctx, err = i.Intercept(ctx)
	}

	ss = ome.GRPCStream(ctx, ss)

	err = handler(srv, ss)
	if err != nil {
		log.Error(fmt.Sprintf("[gRPC stream] %s", method), log.Err(err), log.Field("duration", time.Since(start)))

	} else {
		log.Error(fmt.Sprintf("[gRPC stream] %s", method), log.Field("duration", time.Since(start)))
	}

	return err
}

// NewInterceptorsChain is a chain of interceptors
func NewInterceptorsChain(i ...Interceptor) MergedInterceptor {
	return &interceptorChain{interceptors: i}
}

// Interceptor is a context wrapper which is executed when gRPC function is called
// it can be use to enrich context or verify authentication.
type Interceptor interface {
	// Intercept gets token works with and return a new token
	Intercept(ctx context.Context) (context.Context, error)
}

// InterceptorFunc is an interceptor function
type InterceptorFunc func(ctx context.Context) (context.Context, error)

// Intercept gets token works with and return a new token
func (interceptorFunc InterceptorFunc) Intercept(ctx context.Context) (context.Context, error) {
	return interceptorFunc(ctx)
}

// JwtVerifyFunc is a function that verify jwt passed through authorization header
type JwtVerifyFunc func(ctx context.Context, jwt string) (context.Context, error)

type jwtVerifier struct {
	verifyFunc JwtVerifyFunc
}

func (j *jwtVerifier) Intercept(ctx context.Context) (context.Context, error) {
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

// NewJwtVerifierInterceptor returns a wrapper that detects bearer authorization
func NewJwtVerifierInterceptor(verifyFunc JwtVerifyFunc) *jwtVerifier {
	return &jwtVerifier{
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

		ctx = ome.ContextWithProxyCredentials(ctx, &ome.ProxyCredentials{
			Key:    key,
			Secret: secret,
		})
	}
	return ctx, nil
}

// NewProxyBasicInterceptor returns a context wrapper that detects proxy authorization
func NewProxyBasicInterceptor() *proxyBasic {
	return &proxyBasic{}
}
