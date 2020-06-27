package interceptors

import (
	"encoding/base64"
	ga "github.com/omecodes/common/grpc-authentication"
	"github.com/omecodes/common/log"
	"net/http"
	"strings"
)

func ProxyAuthenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyAuthorizationHeader := r.Header.Get("")
		if proxyAuthorizationHeader != "" {
			decodedBytes, err := base64.StdEncoding.DecodeString(proxyAuthorizationHeader)
			if err != nil {
				log.Error("could not parse Proxy-Authorization", err)
				w.WriteHeader(http.StatusProxyAuthRequired)
				return
			}

			var key string
			var secret string

			splits := strings.Split(string(decodedBytes), ":")
			key = splits[0]
			if len(splits) > 1 {
				secret = splits[1]
			}

			ctx := r.Context()
			r = r.WithContext(ga.ContextWithProxyCredentials(ctx, &ga.ProxyCredentials{
				Key:    key,
				Secret: secret,
			}))
		}

		next.ServeHTTP(w, r)
	})
}
