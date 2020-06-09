package interceptors

import (
	"github.com/omecodes/common/log"
	authpb "github.com/omecodes/common/proto/auth"
	"net/http"
	"strings"
)

type authorizationTokenValidator struct {
	verifier authpb.TokenVerifier
}

func (atv *authorizationTokenValidator) Handle(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorizationHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authorizationHeader, "Bearer ") {
			strJWT := strings.TrimLeft(authorizationHeader, "Bearer ")
			t, err := authpb.ParseJWT(strJWT)
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			state, err := atv.verifier.Verify(r.Context(), t)
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
			ctx = authpb.ContextWithToken(ctx, t)
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

func NewAuthorizationTokenValidator(verifier authpb.TokenVerifier) *authorizationTokenValidator {
	return &authorizationTokenValidator{
		verifier: verifier,
	}
}
