package interceptors

import (
	"github.com/gorilla/securecookie"
	"github.com/omecodes/common/log"
	authpb "github.com/omecodes/common/proto/auth"
	"net/http"
	"strings"
)

type authorizationBearer struct {
	codecs   []securecookie.Codec
	verifier authpb.TokenVerifier
}

func (atv *authorizationBearer) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorizationHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authorizationHeader, "Bearer ") {
			accessToken := strings.TrimLeft(authorizationHeader, "Bearer ")

			strJWT, err := authpb.ExtractJwtFromAccessToken("", accessToken, atv.codecs...)
			if err != nil {
				log.Error("could not extract jwt from access token", err)
				next.ServeHTTP(w, r)
				return
			}

			jwt, err := authpb.ParseJWT(strJWT)
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			state, err := atv.verifier.Verify(r.Context(), jwt)
			if err != nil {
				log.Error("could not verify JWT", err, log.Field("jwt", strJWT))
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			if state != authpb.JWTState_VALID {
				log.Info("invalid JWT", log.Field("jwt", strJWT))
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			// enrich context with
			ctx := r.Context()
			ctx = authpb.ContextWithToken(ctx, jwt)
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

func Oauth2(verifier authpb.TokenVerifier, codecs ...securecookie.Codec) *authorizationBearer {
	return &authorizationBearer{
		codecs:   codecs,
		verifier: verifier,
	}
}
