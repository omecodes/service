package interceptors

import (
	"context"
	"google.golang.org/grpc/metadata"
)

type JwtVerifyFunc func(ctx context.Context, jwt string) (context.Context, error)

type Jwt struct {
	verifyFunc JwtVerifyFunc
}

func (j *Jwt) Intercept(ctx context.Context) (context.Context, error) {
	if ctx == nil {
		return nil, nil
	}

	var err error

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx, nil
	}

	meta := md.Get("authorization")
	if len(meta) != 0 {
		authorization := meta[0]
		ctx, err = j.verifyFunc(ctx, authorization)
	}

	return ctx, err
}

func NewJwt(verifyFunc JwtVerifyFunc) *Jwt {
	return &Jwt{
		verifyFunc: verifyFunc,
	}
}
