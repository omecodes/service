package interceptors

import (
	"net/http"
)

type proxyAuthorizationValidator struct {
	realm     string
	validator func(...string) string
}

func (abv *proxyAuthorizationValidator) Handle(next http.Handler) http.Handler {
	/* reqAuth := &xhttp.RequireAuth {
		Realm: abv.realm,
		Type:  "Basic",
	} */

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		/* proxyAuthorizationHeader := r.Header.Get("")
		username, password, ok := r.BasicAuth()
		if ok {
			foundPassword := abv.validator(username)
			if foundPassword != password {
				xhttp.WriteResponse(w, http.StatusUnauthorized, reqAuth)
				return
			}

			ctx := r.Context()
			ctx = context.WithValue(ctx, context2.Credentials, &authpb.Credentials{Subject:username, Password: password})
			r = r.WithContext(ctx)
		} */
		next.ServeHTTP(w, r)
	})
}

func NewProxyAuthorizationValidator(realm string) *proxyAuthorizationValidator {
	return &proxyAuthorizationValidator{
		realm: realm,
	}
}
