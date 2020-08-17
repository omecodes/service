package service

import (
	"context"
	"github.com/omecodes/common/grpcx"
	authpb "github.com/omecodes/libome/proto/auth"
	"github.com/omecodes/libome/proto/service"
	"google.golang.org/grpc"
)

type initOptions struct {
	registry           pb.Registry
	caProxyCredentials *grpcx.ProxyCredentials
}

type InitOption func(*initOptions)

func WithCACredentials(pc *grpcx.ProxyCredentials) InitOption {
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
				gRPCCallOptions = append(gRPCCallOptions, grpc.PerRPCCredentials(grpcx.NewGRPCClientJwt(strToken)))
			}

		} else if t == CallOptProxyCredentials {
			cred := grpcx.ProxyCredentialsFromContext(ctx)
			if cred != nil {
				gRPCCallOptions = append(gRPCCallOptions, grpc.PerRPCCredentials(grpcx.NewGRPCProxy(
					cred.Key, cred.Secret)))
			}
		}
	}
	return gRPCCallOptions, nil
}
