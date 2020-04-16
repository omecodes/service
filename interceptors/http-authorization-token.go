package interceptors

import (
	authpb "github.com/zoenion/common/proto/auth"
	"log"
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
			t, err := authpb.TokenFromJWT(strJWT)
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			state, err := atv.verifier.Verify(r.Context(), t)
			if err != nil {
				log.Println("could not verify JWT:", err)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			if state != authpb.JWTState_VALID {
				log.Println("Invalid JWT:", strJWT)
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
