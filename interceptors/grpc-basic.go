package interceptors

import (
	"context"
	"encoding/base64"
	"github.com/zoenion/common/errors"
	"github.com/zoenion/service/interceptors/authentication"
	"google.golang.org/grpc/metadata"
	"strings"
)

type Basic struct {
}

func (b *Basic) Intercept(ctx context.Context) (context.Context, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errors.Forbidden
	}

	meta := md.Get("authorization")
	if len(meta) == 0 {
		return ctx, nil
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

		ctx = authentication.ContextWithCredentials(ctx, &authentication.Credentials{
			Username: user,
			Password: secret,
		})
	}
	return ctx, nil
}

func NewBasic() *Basic {
	return &Basic{}
}
