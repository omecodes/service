package interceptors

import (
	"encoding/json"
	"fmt"
	"github.com/mssola/user_agent"
	"github.com/zoenion/common/xhttp"
	"log"
	"net/http"
	"strings"
)

// GRPCTranslatorAuthorization
type GRPCTranslatorAuthorization struct {
	secret string
}

func (gt *GRPCTranslatorAuthorization) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authorization := r.Header.Get("authorization")
		r.Header.Set("authorization", fmt.Sprintf("Gateway %s/%s", gt.secret, authorization))
		next.ServeHTTP(w, r)
	}
}

func NewGRPCTranslatorAuthorization(secret string) *GRPCTranslatorAuthorization {
	return &GRPCTranslatorAuthorization{
		secret: secret,
	}
}

type APIAccess struct {
	gRPCGatewaySecret string
	realm             string
	secret            string
}

func (a *APIAccess) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiAuthorization := r.Header.Get("X-Api-Key")
		if apiAuthorization == "" {
			log.Println("Api access refused")
			xhttp.WriteResponse(w, http.StatusUnauthorized, "API access refused")
			return
		}

		if !strings.HasPrefix(apiAuthorization, a.realm+" ") {
			log.Println("Api access refused")
			xhttp.WriteResponse(w, http.StatusUnauthorized, "API access refused")
			return
		}

		apiAuthorization = strings.TrimPrefix(apiAuthorization, a.realm+" ")
		if apiAuthorization != a.secret {
			xhttp.WriteResponse(w, http.StatusUnauthorized, "API access refused")
			return
		}

		userAuthorization := r.Header.Get("Authorization")
		if userAuthorization != "" {
			r.Header.Set("authorization", fmt.Sprintf("Gateway %s/%s", a.gRPCGatewaySecret, userAuthorization))
		}
		next(w, r)
	}
}

func NewAPIAccess(realm, secret, gatewaySharedSecret string) *APIAccess {
	return &APIAccess{
		secret:            secret,
		realm:             realm,
		gRPCGatewaySecret: gatewaySharedSecret,
	}
}

type Anonymous struct {
	jwtProvider func(string) (string, error)
}

func (a *Anonymous) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authorization := r.Header.Get("authorization")
		if authorization == "" && a.jwtProvider != nil {
			userAgent := r.Header.Get("user_agent")
			au := user_agent.New(userAgent)
			uaBytes, err := json.Marshal(au)
			if err != nil {
				xhttp.WriteResponse(w, http.StatusInternalServerError, nil)
				return
			}

			jwt, err := a.jwtProvider(string(uaBytes))
			if err != nil {
				log.Println("could not get jwt for public user:", err)
				xhttp.WriteResponse(w, http.StatusInternalServerError, nil)
				return
			}
			r.Header.Set("authorization", "Bearer "+jwt)
		}
		next(w, r)
	}
}

func NewAnonymous(jwtProvider func(string) (string, error)) *Anonymous {
	return &Anonymous{jwtProvider: jwtProvider}
}
