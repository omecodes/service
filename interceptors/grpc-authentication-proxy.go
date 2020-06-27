package interceptors

import (
	"context"
	"encoding/base64"
	"github.com/omecodes/common/errors"
	"github.com/omecodes/common/grpc-authentication"
	"google.golang.org/grpc/metadata"
	"strings"
)

type proxyBasic struct{}

func (b *proxyBasic) Intercept(ctx context.Context) (context.Context, error) {
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

		decodedBytes, err := base64.StdEncoding.DecodeString(authorization)
		if err != nil {
			return nil, errors.Forbidden
		}

		var key string
		var secret string

		splits := strings.Split(string(decodedBytes), ":")
		key = splits[0]
		if len(splits) > 1 {
			secret = splits[1]
		}

		ctx = ga.ContextWithProxyCredentials(ctx, &ga.ProxyCredentials{
			Key:    key,
			Secret: secret,
		})
	}
	return ctx, nil
}

func ProxyBasic() *proxyBasic {
	return &proxyBasic{}
}
