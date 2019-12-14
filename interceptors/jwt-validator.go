package interceptors

import (
	"context"
	"github.com/zoenion/common/errors"
	"google.golang.org/grpc/metadata"
)

type JwtVerifyFunc func(ctx context.Context, jwt string) (context.Context, error)

type Jwt struct {
	acceptAnonymous bool
	verifyFunc      JwtVerifyFunc
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
	if authorization == "" && j.acceptAnonymous {
		return ctx, nil
	}

	return j.verifyFunc(ctx, authorization)
}

func NewJwt(verifyFunc JwtVerifyFunc, acceptAnonymous bool) *Jwt {
	return &Jwt{
		acceptAnonymous: acceptAnonymous,
		verifyFunc:      verifyFunc,
	}
}
