package interceptors

import (
	"context"
	"github.com/omecodes/common/errors"
	"github.com/omecodes/common/log"
	"google.golang.org/grpc/metadata"
	"strings"
)

type JwtVerifyFunc func(ctx context.Context, jwt string) (context.Context, error)

type idToken struct {
	verifyFunc JwtVerifyFunc
}

func (j *idToken) Intercept(ctx context.Context) (context.Context, error) {
	var err error

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx, nil
	}

	meta := md.Get("authorization")
	if len(meta) != 0 {
		authorization := meta[0]
		head := authorization[:7]
		if strings.HasPrefix(strings.ToLower(head), "bearer ") {
			ctx, err = j.verifyFunc(ctx, authorization[7:])
			if err != nil {
				log.Error("failed to verify token", err)
				err = errors.Unauthorized
			}
		}
	}

	return ctx, err
}

func Jwt(verifyFunc JwtVerifyFunc) *idToken {
	return &idToken{
		verifyFunc: verifyFunc,
	}
}
