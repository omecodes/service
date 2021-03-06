package service

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/omecodes/common/utils/log"
	"golang.org/x/crypto/acme/autocert"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/omecodes/common/httpx"
	"github.com/omecodes/libome"
	"github.com/omecodes/libome/logs"
)

func (box *Box) StartGateway(params *GatewayParams, nOpts ...NodeOption) error {
	box.serverMutex.Lock()
	defer box.serverMutex.Unlock()

	var options nodeOptions
	for _, o := range nOpts {
		o(&options)
	}
	box.Options.override(options.boxOptions...)
	if params.Name == "" {
		params.Name = uuid.New().String()
	}

	var listener net.Listener
	var err error

	if options.tlsConfig != nil {
		var addr string
		if options.port == 0 {
			addr = box.Options.Host() + ":"
		} else {
			addr = fmt.Sprintf("%s:%d", box.Options.Host(), options.port)
		}
		listener, err = tls.Listen("tcp", addr, options.tlsConfig)
	} else {
		listener, options.tlsConfig, err = box.Options.listen(options.port, params.Security)
	}

	if err != nil {
		return err
	}

	address := listener.Addr().String()
	if box.Options.netMainDomain != "" {
		address = strings.Replace(address, strings.Split(address, ":")[0], box.Options.netMainDomain, 1)
	}
	router := params.ProvideRouter()

	var handler http.Handler

	if len(params.MiddlewareList) > 0 {
		handler = router
		for _, m := range params.MiddlewareList {
			handler = m.Middleware(handler)
		}
	} else {
		handler = httpx.Logger(params.Name).Handle(router)
	}

	handler = httpx.ContextUpdater(func(ctx context.Context) context.Context {
		return ContextWithBox(ctx, box)
	}).Handle(handler)

	logs.Info("starting HTTP server", logs.Details("gateway", params.Name), logs.Details("address", address))
	srv := &http.Server{
		Addr:    address,
		Handler: handler,
	}
	gt := &httpNode{}
	gt.Server = srv
	gt.Address = address
	if options.tlsConfig != nil || params.Security != ome.Security_Insecure {
		gt.Scheme = "https"
	} else {
		gt.Scheme = "http"
	}

	gt.Name = params.Name
	box.httpNodes[params.Name] = gt
	go func() {
		err = srv.Serve(listener)
		if err != nil {
			if err != http.ErrServerClosed {
				logs.Error("http server stopped", logs.Err(err))
			}

			if info, deleted := box.DeleteNode(params.ServiceType, params.ServiceID, params.Name); deleted {
				_ = box.registry.RegisterService(info)
			}
		}
	}()

	if options.register {
		reg, err := box.Options.Registry()
		if err != nil {
			return err
		}

		n := &ome.Node{
			Id:       params.Name,
			Protocol: ome.Protocol_Http,
			Address:  address,
			Security: params.Security,
			Ttl:      -1,
			Meta:     params.Meta,
		}
		info := box.SaveNode(params.ServiceType, params.ServiceID, n)
		err = reg.RegisterService(info)
		if err != nil {
			logs.Error("could not register service", logs.Err(err))
		}
	}
	return nil
}

func (box *Box) StartPublicGateway(params *PublicGatewayParams, nOpts ...NodeOption) error {
	box.serverMutex.Lock()
	defer box.serverMutex.Unlock()

	var options nodeOptions
	for _, o := range nOpts {
		o(&options)
	}
	box.Options.override(options.boxOptions...)

	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(box.Domains()...),
	}
	certManager.Cache = autocert.DirCache(box.workingDir)

	log.Info("starting HTTP Listener on Port 80")
	go func() {
		h := certManager.HTTPHandler(nil)
		if err := http.ListenAndServe(":80", h); err != nil {
			log.Error("listen to port 80 failed", log.Err(err))
		}
	}()

	address := fmt.Sprintf("%s:443", box.Host())
	if box.Options.netMainDomain != "" {
		address = strings.Replace(address, strings.Split(address, ":")[0], box.Options.netMainDomain, 1)
	}

	router := params.ProvideRouter()

	var handler http.Handler

	if len(params.MiddlewareList) > 0 {
		handler = router
		for _, m := range params.MiddlewareList {
			handler = m.Middleware(handler)
		}
	} else {
		handler = router
	}

	logs.Info("starting HTTP server", logs.Details("gateway", params.Name), logs.Details("address", address))
	srv := &http.Server{
		Addr:         address,
		Handler:      handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  120 * time.Second,
		TLSConfig: &tls.Config{
			GetCertificate: certManager.GetCertificate,
		},
	}

	gt := &httpNode{}
	gt.Server = srv
	gt.Address = address
	gt.Scheme = "https"

	gt.Name = params.Name
	box.httpNodes[params.Name] = gt
	go func() {
		err := srv.ListenAndServeTLS("", "")
		if err != nil {
			if err != http.ErrServerClosed {
				logs.Error("http server stopped", logs.Err(err))
			}

			if info, deleted := box.DeleteNode(params.ServiceType, params.ServiceID, params.Name); deleted {
				_ = box.registry.RegisterService(info)
			}
		}
	}()

	if options.register {
		reg, err := box.Options.Registry()
		if err != nil {
			return err
		}

		n := &ome.Node{
			Id:       params.Name,
			Protocol: ome.Protocol_Http,
			Address:  address,
			Security: ome.Security_Acme,
			Ttl:      -1,
			Meta:     params.Meta,
		}
		info := box.SaveNode(params.ServiceType, params.ServiceID, n)
		err = reg.RegisterService(info)
		if err != nil {
			logs.Error("could not register service", logs.Err(err))
		}
	}
	return nil
}

func (box *Box) stopGateways() error {
	box.serverMutex.Lock()
	defer box.serverMutex.Unlock()
	for name, srv := range box.httpNodes {
		err := srv.Stop()
		if err != nil {
			logs.Error(fmt.Sprintf("gateway stopped"), logs.Err(err), logs.Details("node", name))
		}
	}
	return nil
}

func ProxyAuthenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyAuthorizationHeader := r.Header.Get("Proxy-Authorization")
		if proxyAuthorizationHeader != "" {
			authorization := strings.TrimPrefix(proxyAuthorizationHeader, "Basic ")
			decodedBytes, err := base64.StdEncoding.DecodeString(authorization)
			if err != nil {
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
			r = r.WithContext(ome.ContextWithProxyCredentials(ctx, &ome.ProxyCredentials{
				Key:    key,
				Secret: secret,
			}))
		}

		next.ServeHTTP(w, r)
	})
}

type authorizationBearer struct {
	codecs   []securecookie.Codec
	verifier ome.TokenVerifier
}

func (atv *authorizationBearer) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorizationHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authorizationHeader, "Bearer ") {
			accessToken := strings.TrimLeft(authorizationHeader, "Bearer ")

			strJWT, err := ome.ExtractJwtFromAccessToken("", accessToken, atv.codecs...)
			if err != nil {
				//logs.Error("could not extract jwt from access token", logs.Err(err))
				next.ServeHTTP(w, r)
				return
			}

			jwt, err := ome.ParseJWT(strJWT)
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			state, err := atv.verifier.Verify(r.Context(), jwt)
			if err != nil {
				logs.Error("could not verify JWT", logs.Err(err), logs.Details("jwt", strJWT))
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			if state != ome.JWTState_Valid {
				logs.Info("invalid JWT", logs.Details("jwt", strJWT))
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			// enrich context with
			ctx := r.Context()
			ctx = ome.ContextWithToken(ctx, jwt)
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

func Oauth2(verifier ome.TokenVerifier, codecs ...securecookie.Codec) *authorizationBearer {
	return &authorizationBearer{
		codecs:   codecs,
		verifier: verifier,
	}
}

type authorizationJWT struct {
	verifier ome.TokenVerifier
}

func (atv *authorizationJWT) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorizationHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authorizationHeader, "Bearer ") {
			strJWT := strings.TrimLeft(authorizationHeader, "Bearer ")
			if strings.Count(strJWT, ".") != 2 {
				logs.Info("bearer info might be access token. Starting access token introspection")

				box := BoxFromContext(r.Context())
				reg, err := box.Registry()
				if err != nil {
					logs.Error("error while getting registry server in registry")
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				info, err := reg.FirstOfType(ome.AuthenticationServiceType)
				if err != nil {
					logs.Error("could not find authentication server in registry")
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				for _, node := range info.Nodes {
					if node.Protocol == ome.Protocol_Http {
						endpoint := fmt.Sprintf("https://%s/token/introspect", node.Address)
						client := http.Client{}
						if node.Security != ome.Security_Insecure {
							// by default no mutual TLS
							tc, err := box.ClientTLS()
							if err != nil {
								logs.Error("failed to get connection TLS config", logs.Err(err))
								w.WriteHeader(http.StatusInternalServerError)
								return
							}

							client.Transport = &http.Transport{TLSClientConfig: tc}
						}

						form := url.Values{}
						form.Add("token", strJWT)

						req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
						if err != nil {
							logs.Error("failed to create token introspection request", logs.Err(err))
							w.WriteHeader(http.StatusInternalServerError)
							return
						}

						req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
						req.SetBasicAuth(box.Options.caAPIKey, box.Options.caAPISecret)

						rsp, err := client.Do(req)
						if err != nil {
							logs.Error("could not send request token introspection", logs.Err(err))
							w.WriteHeader(http.StatusInternalServerError)
							return
						}

						if rsp.StatusCode != 200 {
							logs.Error("token introspection failed", logs.Details("status", rsp.Status))
							w.WriteHeader(http.StatusForbidden)
							return
						}

						var jwt ome.JWT
						err = json.NewDecoder(rsp.Body).Decode(&jwt)
						if err != nil {
							logs.Error("could not read introspection body response", logs.Err(err))
							w.WriteHeader(http.StatusForbidden)
							return
						}

						ctx := r.Context()
						ctx = ome.ContextWithToken(ctx, &jwt)
						r = r.WithContext(ctx)
					}
				}
			} else {
				t, err := ome.ParseJWT(strJWT)
				if err != nil {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}

				state, err := atv.verifier.Verify(r.Context(), t)
				if err != nil {
					logs.Error("could not verify JWT", logs.Err(err), logs.Details("jwt", strJWT))
					w.WriteHeader(http.StatusUnauthorized)
					return
				}

				if state != ome.JWTState_Valid {
					logs.Info("invalid JWT", logs.Details("jwt", strJWT))
					w.WriteHeader(http.StatusUnauthorized)
					return
				}

				// enrich context with
				ctx := r.Context()
				ctx = ome.ContextWithToken(ctx, t)
				r = r.WithContext(ctx)
			}
		}
		next.ServeHTTP(w, r)
	})
}

func JWT(verifier ome.TokenVerifier) *authorizationJWT {
	return &authorizationJWT{
		verifier: verifier,
	}
}
