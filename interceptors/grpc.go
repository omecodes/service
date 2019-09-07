package interceptors

import (
	"context"
	"fmt"
	"github.com/zoenion/common/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"log"
	"path"
	"strings"
	"time"
)

//
type gRPCServerAccessAuthentication struct {
	access  string
	methods []string
}

func (gi *gRPCServerAccessAuthentication) InterceptUnary(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	start := time.Now()

	methodName := path.Base(info.FullMethod)
	var (
		rsp interface{}
		err error
	)

	for _, method := range gi.methods {
		if method == methodName {
			md, ok := metadata.FromIncomingContext(ctx)
			if !ok {
				err = errors.Forbidden
			}

			authorizationValues := md.Get("authorization")
			if len(authorizationValues) == 0 {
				err = errors.Forbidden
			}

			authorization := strings.TrimPrefix(authorizationValues[0], "Access ")
			if authorization != gi.access {
				err = errors.Forbidden
			}
			break
		}
	}

	if err == nil {
		rsp, err = handler(ctx, req)
	}

	log.Printf("gRPC request - Method:%s\tDuration:%s\tError:%v\n",
		methodName,
		time.Since(start),
		err)

	return rsp, err
}

func (gi *gRPCServerAccessAuthentication) InterceptStream(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	start := time.Now()
	methodName := path.Base(info.FullMethod)

	var err error
	for _, method := range gi.methods {
		if method == methodName {
			md, ok := metadata.FromIncomingContext(ss.Context())
			if !ok {
				err = errors.Forbidden
			}

			authorizationValues := md.Get("authorization")
			if len(authorizationValues) == 0 {
				err = errors.Forbidden
			}

			authorization := strings.TrimPrefix(authorizationValues[0], "Access ")
			if authorization != gi.access {
				err = errors.Forbidden
			}
			break
		}
	}
	if err == nil {
		err = handler(srv, newLoggedStream(ss))
	}

	log.Printf("gRPC request - Method:%s\tDuration:%s\tError:%v\n", methodName, time.Since(start), err)
	return err
}

func NewGRPCServerAccessAuthentication(accessKey, accessSecret string, methods ...string) *gRPCServerAccessAuthentication {
	return &gRPCServerAccessAuthentication{
		access:  fmt.Sprintf("%s:%s", accessKey, accessSecret),
		methods: methods,
	}
}

type gRPCServerAuthentication struct {
	methodAuthenticator GRPCMethodAuthenticator
}

func (gi *gRPCServerAuthentication) InterceptUnary(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	start := time.Now()

	methodName := path.Base(info.FullMethod)
	var (
		rsp interface{}
		err error
	)

	err = gi.methodAuthenticator(ctx, methodName)
	if err == nil {
		rsp, err = handler(ctx, req)
	}

	log.Printf("gRPC request - Method:%s\tDuration:%s\tError:%v\n",
		methodName,
		time.Since(start),
		err)

	return rsp, err
}

func (gi *gRPCServerAuthentication) InterceptStream(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	start := time.Now()
	methodName := path.Base(info.FullMethod)

	err := gi.methodAuthenticator(ss.Context(), methodName)
	if err == nil {
		err = handler(srv, newLoggedStream(ss))
	}

	log.Printf("gRPC request - Method:%s\tDuration:%s\tError:%v\n",
		methodName,
		time.Since(start),
		err)
	return err
}

func NewGRPCServerAuthentication(ma GRPCMethodAuthenticator) *gRPCServerAuthentication {
	return &gRPCServerAuthentication{
		methodAuthenticator: ma,
	}
}

type loggedStream struct {
	grpc.ServerStream
}

func (w *loggedStream) RecvMsg(m interface{}) error {
	log.Printf("Receive a message (Type: %T) at %s\n", m, time.Now().Format(time.RFC3339))
	return w.ServerStream.RecvMsg(m)
}

func (w *loggedStream) SendMsg(m interface{}) error {
	log.Printf("Send a message (Type: %T) at %v\n", m, time.Now().Format(time.RFC3339))
	return w.ServerStream.SendMsg(m)
}

func newLoggedStream(s grpc.ServerStream) grpc.ServerStream {
	return &loggedStream{s}
}

type GRPC interface {
	InterceptUnary(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error)
	InterceptStream(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error
}

type JwtVerifyFunc func(ctx context.Context, jwt string) error

type ValidationLink interface {
	Name() string
	Validate(ctx context.Context) (context.Context, error)
}

type GRPCMethodAuthenticator func(ctx context.Context, method string) error

type MethodRules map[string]*InterceptRule

type InterceptRule struct {
	Secure bool
	Links  []string
}

const (
	JWTValidator     = "jwt"
	BasicValidator   = "basic"
	GatewayValidator = "gateway"
)

type chainedInterceptor struct {
	rules      MethodRules
	validators map[string]ValidationLink
}

func (interceptor *chainedInterceptor) InterceptUnary(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	var err error
	start := time.Now()
	method := path.Base(info.FullMethod)
	log.Printf("gRPC request - Method:%s at %s\t\n", method, start.String())

	rule := interceptor.rules[method]
	if rule != nil {
		for _, link := range rule.Links {
			v, found := interceptor.validators[link]
			if !found {
				log.Printf("gRPC request - Method:%s\tDuration:%s\tError:%v\n", method, time.Since(start), errors.New("validator not found"))
				return nil, errors.Forbidden
			}

			ctx, err = v.Validate(ctx)
			if err != nil {
				log.Printf("gRPC request - Method:%s\tDuration:%s\tError:%v\n", method, time.Since(start), err)
				return nil, err
			}
		}
	}

	rsp, err := handler(ctx, req)
	log.Printf("gRPC request - Method:%s\tDuration:%s\tError:%v\n", method, time.Since(start), err)
	return rsp, err
}

func (interceptor *chainedInterceptor) InterceptStream(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	var err error
	start := time.Now()
	ctx := ss.Context()
	method := path.Base(info.FullMethod)
	log.Printf("gRPC request - Method:%s at %s\t\n", method, start.String())

	rule := interceptor.rules[method]
	if rule != nil {
		for _, link := range rule.Links {
			v, found := interceptor.validators[link]
			if !found {
				log.Printf("gRPC request - Method:%s\tDuration:%s\tError:%v\n", method, time.Since(start), errors.New("validator not found"))
				return errors.Forbidden
			}

			ctx, err = v.Validate(ctx)
			if err != nil {
				log.Printf("gRPC request - Method:%s\tDuration:%s\tError:%v\n", method, time.Since(start), err)
				return err
			}
		}
	}

	err = handler(srv, ss)
	log.Printf("gRPC request - Method:%s\tDuration:%s\tError:%v\n", method, time.Since(start), err)
	return err
}

func NewChainedInterceptor(rules MethodRules, links ...ValidationLink) GRPC {
	chain := &chainedInterceptor{rules: rules}
	chain.validators = map[string]ValidationLink{}
	for _, link := range links {
		chain.validators[link.Name()] = link
	}
	return chain
}
