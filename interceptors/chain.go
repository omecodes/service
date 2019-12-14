package interceptors

import (
	"context"
	"github.com/zoenion/common/errors"
	"google.golang.org/grpc"
	"log"
	"path"
	"time"
)

const (
	JWTValidator     = "jwt"
	BasicValidator   = "basic"
	GatewayValidator = "gateway"
	CtxWrap          = "context-wrap"
)

type GRPCMethodAuthenticator func(ctx context.Context, method string) error

type MethodRules map[string]*InterceptRule

type InterceptRule struct {
	Secure bool
	Links  []string
}

type ValidationLink interface {
	Name() string
	Validate(ctx context.Context) (context.Context, error)
}

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
