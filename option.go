package service

import (
	"context"
	"github.com/zoenion/common/grpc-authentication"
	"github.com/zoenion/common/jcon"
	authpb "github.com/zoenion/common/proto/auth"
	"github.com/zoenion/service/discovery"
	"google.golang.org/grpc"
)

type initOptions struct {
	registry             discovery.Registry
	RegistryServerDBConf jcon.Map
	caProxyCredentials   *ga.ProxyCredentials
}

type InitOption func(*initOptions)

func WithCACredentials(pc *ga.ProxyCredentials) InitOption {
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
			token := authpb.TokenFromContext(ctx)
			strToken, err := authpb.String(token)
			if err != nil {
				return nil, err
			}

			if token != nil {
				gRPCCallOptions = append(gRPCCallOptions, grpc.PerRPCCredentials(ga.NewGRPCClientJwt(strToken)))
			}

		} else if t == CallOptProxyCredentials {
			cred := ga.ProxyCredentialsFromContext(ctx)
			if cred != nil {
				gRPCCallOptions = append(gRPCCallOptions, grpc.PerRPCCredentials(ga.NewGRPCProxy(
					cred.Key, cred.Secret)))
			}
		}
	}
	return gRPCCallOptions, nil
}