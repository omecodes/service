package interceptors

import (
	"context"
	"encoding/base64"
	"github.com/zoenion/service/errors"
	"google.golang.org/grpc/metadata"
	"strings"
)

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
