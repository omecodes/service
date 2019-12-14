package interceptors

import (
	"context"
	"github.com/zoenion/common/errors"
	"google.golang.org/grpc/metadata"
	"strings"
)

type Gateway struct {
	sharedSecret string
}

func (g *Gateway) Name() string {
	return GatewayValidator
}

func (g *Gateway) Validate(ctx context.Context) (context.Context, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return g.validateCert(ctx)
	}

	meta := md.Get("authorization")
	if len(meta) == 0 {
		return g.validateCert(ctx)
	}

	authorization := meta[0]
	if strings.HasPrefix(authorization, "Gateway ") {
		authorization := strings.TrimPrefix(authorization, "Gateway ")
		parts := strings.Split(authorization, "/")
		if len(parts) != 2 {
			return nil, errors.Forbidden
		}
		secret := parts[0]
		authorization = parts[1]

		if secret != g.sharedSecret {
			return nil, errors.Forbidden
		}

		md.Set("authorization", parts[1])
		ctx = metadata.NewIncomingContext(ctx, md)
	}
	return ctx, nil
}

func (g *Gateway) validateCert(ctx context.Context) (context.Context, error) {
	return ctx, nil
}

func NewGateway(sharedSecret string) *Gateway {
	return &Gateway{
		sharedSecret: sharedSecret,
	}
}
