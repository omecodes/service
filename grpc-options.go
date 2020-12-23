package service

import (
	"context"
	"crypto/tls"
	ome "github.com/omecodes/libome"
	"google.golang.org/grpc"
)

type nodeOptions struct {
	register     bool
	port         int
	tlsConfig    *tls.Config
	interceptors []ome.GrpcContextUpdater
	md           MD
	boxOptions   []Option
}

type NodeOption func(options *nodeOptions)

func WithPort(port int) NodeOption {
	return func(options *nodeOptions) {
		options.port = port
	}
}

func WithTLS(t *tls.Config) NodeOption {
	return func(options *nodeOptions) {
		options.tlsConfig = t
	}
}

func WithInterceptor(interceptors ...ome.GrpcContextUpdater) NodeOption {
	return func(options *nodeOptions) {
		options.interceptors = append(options.interceptors, interceptors...)
	}
}

func WithMeta(m MD) NodeOption {
	return func(options *nodeOptions) {
		options.md = m
	}
}

func Register(register bool) NodeOption {
	return func(options *nodeOptions) {
		options.register = register
	}
}

func GlobalOptions(opts ...Option) NodeOption {
	return func(options *nodeOptions) {
		options.boxOptions = opts
	}
}

type GRPCCallOption int

const (
	CallOptToken GRPCCallOption = iota + 1
	CallOptProxyCredentials
	CallOptBasic
)

func GRPCCallOptionsFromContext(ctx context.Context, ot ...GRPCCallOption) ([]grpc.CallOption, error) {
	var gRPCCallOptions []grpc.CallOption

	for _, t := range ot {
		if t == CallOptToken {
			token := ome.TokenFromContext(ctx)
			strToken, err := ome.String(token)
			if err != nil {
				return nil, err
			}

			if token != nil {
				gRPCCallOptions = append(gRPCCallOptions, grpc.PerRPCCredentials(ome.NewGRPCClientJwt(strToken)))
			}

		} else if t == CallOptProxyCredentials {
			cred := ome.ProxyCredentialsFromContext(ctx)
			if cred != nil {
				gRPCCallOptions = append(gRPCCallOptions, grpc.PerRPCCredentials(ome.NewGRPCProxy(
					cred.Key, cred.Secret)))
			}
		}
	}
	return gRPCCallOptions, nil
}
