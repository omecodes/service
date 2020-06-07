package interceptors

import (
	"context"
	"encoding/base64"
	"github.com/omecodes/common/errors"
	"github.com/omecodes/common/grpc-authentication"
	"google.golang.org/grpc/metadata"
	"strings"
)

type basic struct {
}

func (b *basic) Intercept(ctx context.Context) (context.Context, error) {
	if ctx == nil {
		return ctx, nil
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errors.Forbidden
	}

	meta := md.Get("authorization")
	if len(meta) == 0 {
		return ctx, nil
	}

	authorization := meta[0]
	head := authorization[:6]
	if strings.HasPrefix(strings.ToLower(head), "basic ") {
		authorization = authorization[6:]

		bytes, err := base64.StdEncoding.DecodeString(authorization)
		if err != nil {
			return ctx, errors.Forbidden
		}

		parts := strings.Split(string(bytes), ":")
		if len(parts) != 2 {
			return ctx, errors.Forbidden
		}

		user := parts[0]
		secret := parts[1]

		ctx = ga.ContextWithCredentials(ctx, &ga.Credentials{
			Username: user,
			Password: secret,
		})
	}
	return ctx, nil
}

func Basic() *basic {
	return &basic{}
}
