package service

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/foomo/simplecert"
	"github.com/foomo/tlsconfig"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/omecodes/common/httpx"
	"github.com/omecodes/common/utils/log"
	"github.com/omecodes/libome"
)

func (box *Box) StartGateway(params *GatewayParams, nOpts ...NodeOption) error {
	box.serverMutex.Lock()
	defer box.serverMutex.Unlock()

	var options nodeOptions
	for _, o := range nOpts {
		o(&options)
	}
	box.options.override(options.boxOptions...)

	var listener net.Listener
	var err error

	if options.tlsConfig != nil {
		var addr string
		if options.port == 0 {
			addr = box.options.Host() + ":"
		} else {
			addr = fmt.Sprintf("%s:%d", box.options.Host(), options.port)
		}
		listener, err = tls.Listen("tcp", addr, options.tlsConfig)
	} else {
		listener, options.tlsConfig, err = box.options.listen(options.port, params.Security)
	}

	if err != nil {
		return err
	}

	address := listener.Addr().String()
	if box.options.netMainDomain != "" {
		address = strings.Replace(address, strings.Split(address, ":")[0], box.options.netMainDomain, 1)
	}
	router := params.ProvideRouter()

	var handler http.Handler

	if len(params.MiddlewareList) > 0 {
		handler = router
		for _, m := range params.MiddlewareList {
			handler = m.Middleware(handler)
		}
	} else {
		handler = httpx.Logger(params.Node.Id).Handle(router)
	}

	handler = httpx.ContextUpdater(func(ctx context.Context) context.Context {
		return ContextWithBox(ctx, box)
	}).Handle(handler)

	log.Info("starting HTTP server", log.Field("gateway", params.Node.Id), log.Field("address", address))
	srv := &http.Server{
		Addr:    address,
		Handler: handler,
	}
	gt := &httpNode{}
	gt.Server = srv
	gt.Address = address
	if options.tlsConfig != nil || params.Node.Security != ome.Security_Insecure {
		gt.Scheme = "https"
	} else {
		gt.Scheme = "http"
	}

	gt.Name = params.Node.Id
	box.httpNodes[params.Node.Id] = gt
	go func() {
		err = srv.Serve(listener)
		if err != nil {
			if err != http.ErrServerClosed {
				log.Error("http server stopped", log.Err(err))
			}

			if box.info != nil {
				var newNodeList []*ome.Node
				for _, node := range box.info.Nodes {
					if node.Id != params.Node.Id {
						newNodeList = append(newNodeList, node)
					}
				}
				box.info.Nodes = newNodeList
				_ = box.registry.RegisterService(box.info)
			}
		}
	}()

	if options.register {
		registry := box.Registry()
		n := params.Node
		n.Address = address
		if box.info == nil {
			box.info = new(ome.ServiceInfo)
			box.info.Id = box.Name()
			box.info.Type = params.ServiceType
			if box.info.Meta == nil {
				box.info.Meta = map[string]string{}
			}
		}
		box.info.Nodes = append(box.info.Nodes, n)

		// gt.RegistryID, err = box.registry.RegisterService(info, ome.ActionOnRegisterExistingService_AddNodes|ome.ActionOnRegisterExistingService_UpdateExisting)
		err = registry.RegisterService(box.info)
		if err != nil {
			log.Error("could not register gateway", log.Err(err), log.Field("name", params.Node.Id))
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
	box.options.override(options.boxOptions...)

	cacheDir := filepath.Join(box.workingDir, "lets-encrypt")
	err := os.MkdirAll(cacheDir, os.ModePerm)
	if err != nil {
		return err
	}

	cfg := simplecert.Default
	cfg.Domains = box.Domains()
	cfg.CacheDir = cacheDir
	cfg.SSLEmail = params.Email
	cfg.DNSProvider = "cloudflare"

	certReloadAgent, err := simplecert.Init(cfg, nil)
	if err != nil {
		return err
	}

	log.Info("starting HTTP Listener on Port 80")
	go func() {
		if err := http.ListenAndServe(":80", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			httpx.Redirect(w, &httpx.RedirectURL{
				URL:         fmt.Sprintf("https://%s:443%s", box.netMainDomain, r.URL.Path),
				Code:        http.StatusPermanentRedirect,
				ContentType: "text/html",
			})
		})); err != nil {
			log.Error("listen to port 80 failed", log.Err(err))
		}
	}()

	tlsConf := tlsconfig.NewServerTLSConfig(tlsconfig.TLSModeServerStrict)
	tlsConf.GetCertificate = certReloadAgent.GetCertificateFunc()

	address := fmt.Sprintf("%s:443", box.Host())
	if box.options.netMainDomain != "" {
		address = strings.Replace(address, strings.Split(address, ":")[0], box.options.netMainDomain, 1)
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

	log.Info("starting HTTP server", log.Field("gateway", params.Node.Id), log.Field("address", address))
	srv := &http.Server{
		Addr:         address,
		Handler:      handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  120 * time.Second,
		TLSConfig:    tlsConf,
	}

	gt := &httpNode{}
	gt.Server = srv
	gt.Address = address
	gt.Scheme = "https"

	gt.Name = params.Node.Id
	box.httpNodes[params.Node.Id] = gt
	go func() {
		err := srv.ListenAndServeTLS("", "")
		if err != nil {
			if err != http.ErrServerClosed {
				log.Error("http server stopped", log.Err(err))
			}

			if box.info != nil {
				var newNodeList []*ome.Node
				for _, node := range box.info.Nodes {
					if node.Id != params.Node.Id {
						newNodeList = append(newNodeList, node)
					}
				}
				box.info.Nodes = newNodeList
				_ = box.registry.RegisterService(box.info)
			}
		}
	}()

	if options.register {
		n := params.Node
		n.Address = address
		if box.info == nil {
			box.info = new(ome.ServiceInfo)
			box.info.Id = box.Name()
			box.info.Type = params.ServiceType
			if box.info.Meta == nil {
				box.info.Meta = map[string]string{}
			}
		}
		box.info.Nodes = append(box.info.Nodes, n)

		// gt.RegistryID, err = box.registry.RegisterService(info, ome.ActionOnRegisterExistingService_AddNodes|ome.ActionOnRegisterExistingService_UpdateExisting)
		err := box.registry.RegisterService(box.info)
		if err != nil {
			log.Error("could not register gateway", log.Err(err), log.Field("name", params.Node.Id))
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
			log.Error(fmt.Sprintf("gateway stopped"), log.Err(err), log.Field("node", name))
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
				//log.Error("could not extract jwt from access token", log.Err(err))
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
				log.Error("could not verify JWT", log.Err(err), log.Field("jwt", strJWT))
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			if state != ome.JWTState_Valid {
				log.Info("invalid JWT", log.Field("jwt", strJWT))
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
				log.Info("bearer info might be access token. Starting access token introspection")

				box := BoxFromContext(r.Context())
				reg := box.Registry()
				info, err := reg.FirstOfType(ome.AuthenticationServiceType)
				if err != nil {
					log.Error("could not find authentication server in registry")
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				for _, node := range info.Nodes {
					if node.Protocol == ome.Protocol_Http {
						endpoint := fmt.Sprintf("https://%s/token/introspect", node.Address)
						client := http.Client{}
						if node.Security != ome.Security_Insecure {
							// by default no mutual TLS
							client.Transport = &http.Transport{TLSClientConfig: box.ClientTLS()}
						}

						form := url.Values{}
						form.Add("token", strJWT)

						req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
						if err != nil {
							log.Error("failed to create token introspection request", log.Err(err))
							w.WriteHeader(http.StatusInternalServerError)
							return
						}

						req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
						req.SetBasicAuth(box.options.caAPIKey, box.options.caAPISecret)

						rsp, err := client.Do(req)
						if err != nil {
							log.Error("could not send request token introspection", log.Err(err))
							w.WriteHeader(http.StatusInternalServerError)
							return
						}

						if rsp.StatusCode != 200 {
							log.Error("token introspection failed", log.Field("status", rsp.Status))
							w.WriteHeader(http.StatusForbidden)
							return
						}

						var jwt ome.JWT
						err = json.NewDecoder(rsp.Body).Decode(&jwt)
						if err != nil {
							log.Error("could not read introspection body response", log.Err(err))
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
					log.Error("could not verify JWT", log.Err(err), log.Field("jwt", strJWT))
					w.WriteHeader(http.StatusUnauthorized)
					return
				}

				if state != ome.JWTState_Valid {
					log.Info("invalid JWT", log.Field("jwt", strJWT))
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
