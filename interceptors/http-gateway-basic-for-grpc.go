package interceptors

import (
	"fmt"
	"github.com/zoenion/common/xhttp"
	"net/http"
)

type basicAuthForGRPC struct {
	realm, username, password, gatewaySecret string
}

func (sb *basicAuthForGRPC) Handle(next http.HandlerFunc) http.HandlerFunc {
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

func NewServerBasic(gatewaySecret, realm, username, password string) *basicAuthForGRPC {
	return &basicAuthForGRPC{
		realm:         realm,
		username:      username,
		password:      password,
		gatewaySecret: gatewaySecret,
	}
}

type basicAuthForGRPCWithAuthenticationFunc struct {
	realm, gatewaySecret string
	credentialsProvider  func(string) string
}

func (sb *basicAuthForGRPCWithAuthenticationFunc) Handle(next http.HandlerFunc) http.HandlerFunc {
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

		if password != sb.credentialsProvider(username) {
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

func NewBasicWithAuthenticationFunc(gatewaySecret, realm string, provider func(string) string) *basicAuthForGRPCWithAuthenticationFunc {
	return &basicAuthForGRPCWithAuthenticationFunc{
		realm:               realm,
		gatewaySecret:       gatewaySecret,
		credentialsProvider: provider,
	}
}
