package interceptors

import (
	"github.com/gorilla/securecookie"
	"github.com/zoenion/common/log"
	"github.com/zoenion/common/oauth2"
	authpb "github.com/zoenion/common/proto/auth"
	"net/http"
	"strings"
)

type authorizationAccessTokenValidator struct {
	codecs []securecookie.Codec
	verifier authpb.TokenVerifier
}

func (atv *authorizationAccessTokenValidator) Handle(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorizationHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authorizationHeader, "Bearer ") {
			accessToken := strings.TrimLeft(authorizationHeader, "Bearer ")

			strJWT, err := oauth2.ExtractJwtFromAccessToken("", accessToken, atv.codecs...)
			if err != nil {
				log.Error("could not extract jwt from access token", err)
				next.ServeHTTP(w, r)
				return
			}

			jwt, err := authpb.TokenFromJWT(strJWT)
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

func NewAuthorizationAccessTokenValidator(verifier authpb.TokenVerifier, codecs ...securecookie.Codec) *authorizationAccessTokenValidator {
	return &authorizationAccessTokenValidator{
		codecs: codecs,
		verifier: verifier,
	}
}
