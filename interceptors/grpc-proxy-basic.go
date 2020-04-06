package interceptors

import (
	"context"
	"encoding/base64"
	"github.com/zoenion/common/errors"
	"github.com/zoenion/service/interceptors/authentication"
	"google.golang.org/grpc/metadata"
	"strings"
)

type ProxyBasic struct {
}

func (b *ProxyBasic) Intercept(ctx context.Context) (context.Context, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errors.Forbidden
	}

	meta := md.Get("proxy-authorization")
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

		ctx = authentication.ContextWithProxyCredentials(ctx, &authentication.ProxyCredentials{
			Key:    user,
			Secret: secret,
		})
	}
	return ctx, nil
}

func NewProxyBasic() *ProxyBasic {
	return &ProxyBasic{}
}
