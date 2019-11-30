package interceptors

import (
	"fmt"
	"github.com/zoenion/common/xhttp"
	"net/http"
)

type ServerBasic struct {
	realm, username, password, gatewaySecret string
}

func (sb *ServerBasic) Handle(next http.HandlerFunc) http.HandlerFunc {
	reqAuth := &xhttp.RequireAuth{
		Realm: sb.realm,
		Type:  "Basic",
	}

	return func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok {
			xhttp.WriteResponse(w, http.StatusUnauthorized, reqAuth)
			return
		}

		if username != sb.username || password != sb.password {
			xhttp.WriteResponse(w, http.StatusUnauthorized, reqAuth)
			return
		}

		userAuthorization := r.Header.Get("Authorization")
		if userAuthorization != "" {
			r.Header.Set("authorization", fmt.Sprintf("Gateway %s/%s", sb.gatewaySecret, userAuthorization))
		}
		next(w, r)
	}
}

func NewServerBasic(gatewaySecret, realm, username, password string) *ServerBasic {
	return &ServerBasic{
		realm:         realm,
		username:      username,
		password:      password,
		gatewaySecret: gatewaySecret,
	}
}