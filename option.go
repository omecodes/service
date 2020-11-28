package service

import (
	"context"
	"google.golang.org/grpc"

	"github.com/omecodes/libome"
)

type initOptions struct {
	registry           ome.Registry
	caProxyCredentials *ome.ProxyCredentials
}

type InitOption func(*initOptions)

func WithCACredentials(pc *ome.ProxyCredentials) InitOption {
	return func(opts *initOptions) {
		opts.caProxyCredentials = pc
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
