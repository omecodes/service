package interceptors

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"github.com/zoenion/common/errors"
	"google.golang.org/grpc/metadata"
	"strings"
)

type Gateway struct {
	sharedSecret string
	ca           *x509.Certificate
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

func NewGateway(sharedSecret string, caCert *x509.Certificate) *Gateway {
	return &Gateway{
		sharedSecret: sharedSecret,
		ca:           caCert,
	}
}

type Jwt struct {
	verifyFunc JwtVerifyFunc
}

func (j *Jwt) Name() string {
	return JWTValidator
}

func (j *Jwt) Validate(ctx context.Context) (context.Context, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errors.Forbidden
	}

	meta := md.Get("authorization")
	if len(meta) == 0 {
		return nil, errors.Forbidden
	}

	authorization := meta[0]

	err := j.verifyFunc(ctx, authorization)
	return ctx, err
}

func NewJwt(verifyFunc JwtVerifyFunc) *Jwt {
	return &Jwt{verifyFunc: verifyFunc}
}

type Basic struct {
	realm          string
	secretProvider func(in ...string) string
}

func (b *Basic) Name() string {
	return BasicValidator
}

func (b *Basic) Validate(ctx context.Context) (context.Context, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errors.Forbidden
	}

	meta := md.Get("authorization")
	if len(meta) == 0 {
		return nil, errors.Forbidden
	}

	authorization := meta[0]
	if strings.HasPrefix(authorization, "Basic ") {
		authorization = strings.TrimPrefix(authorization, "Basic ")

		bytes, err := base64.StdEncoding.DecodeString(authorization)
		if err != nil {
			return nil, errors.Forbidden
		}

		parts := strings.Split(string(bytes), ":")
		if len(parts) != 2 {
			return nil, errors.Forbidden
		}

		user := parts[0]
		secret := parts[1]

		if secret != b.secretProvider(user) {
			return nil, errors.Forbidden
		}
		return ctx, nil
	} else {
		return nil, errors.Forbidden
	}
}

func NewBasic(realm string, secretProvider func(in ...string) string) *Basic {
	return &Basic{
		realm:          realm,
		secretProvider: secretProvider,
	}
}
