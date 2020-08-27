package service

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/gorilla/securecookie"
	"github.com/omecodes/common/httpx"
	"github.com/omecodes/common/utils/log"
	ome "github.com/omecodes/libome"
	authpb "github.com/omecodes/libome/proto/auth"
	pb "github.com/omecodes/libome/proto/service"
	"golang.org/x/crypto/acme/autocert"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

func (box *Box) StartGateway(params *GatewayParams) error {
	box.serverMutex.Lock()
	defer box.serverMutex.Unlock()

	listener, err := box.listen(params.Port, params.Node.Security, params.Tls)
	if err != nil {
		return err
	}

	address := listener.Addr().String()
	if box.params.Domain != "" {
		address = strings.Replace(address, strings.Split(address, ":")[0], box.params.Domain, 1)
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
	if params.Tls != nil || params.Node.Security != pb.Security_None {
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
				var newNodeList []*pb.Node
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

	if !box.params.Autonomous && box.registry != nil {
		n := params.Node
		n.Address = address
		if box.info == nil {
			box.info = new(pb.Info)
			box.info.Id = box.Name()
			box.info.Type = params.ServiceType
			if box.info.Meta == nil {
				box.info.Meta = map[string]string{}
			}
		}
		box.info.Nodes = append(box.info.Nodes, n)

		// gt.RegistryID, err = box.registry.RegisterService(info, pb.ActionOnRegisterExistingService_AddNodes|pb.ActionOnRegisterExistingService_UpdateExisting)
		err = box.registry.RegisterService(box.info)
		if err != nil {
			log.Error("could not register gateway", log.Err(err), log.Field("name", params.Node.Id))
		}
	}
	return nil
}

func (box *Box) StartAcmeGateway(params *AcmeGatewayParams) error {
	box.serverMutex.Lock()
	defer box.serverMutex.Unlock()

	cacheDir := filepath.Dir(box.CertificateFilename())
	hostPolicy := func(ctx context.Context, host string) error {
		allowedHost := box.Domain()
		if host == allowedHost {
			return nil
		}
		return fmt.Errorf("acme/autocert: only %s host is allowed", allowedHost)
	}
	man := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: hostPolicy,
		Cache:      autocert.DirCache(cacheDir),
	}

	address := fmt.Sprintf("%s:443", box.Host())
	if box.params.Domain != "" {
		address = strings.Replace(address, strings.Split(address, ":")[0], box.params.Domain, 1)
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
		TLSConfig:    &tls.Config{GetCertificate: man.GetCertificate},
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
				var newNodeList []*pb.Node
				for _, node := range box.info.Nodes {
					if node.Id != params.Node.Id {
						newNodeList = append(newNodeList, node)
					}
				}
				box.info.Nodes = newNodeList
				_ = box.registry.RegisterService(box.info)
			}

			httpSrv := &http.Server{
				ReadTimeout:  5 * time.Second,
				WriteTimeout: 5 * time.Second,
				IdleTimeout:  120 * time.Second,
				Handler:      man.HTTPHandler(srv.Handler),
				Addr:         fmt.Sprintf("%s:80", box.Host()),
			}
			err = httpSrv.ListenAndServe()
			if err != nil {
				log.Error("failed to run acme server", log.Err(err))
			}
		}
	}()

	if !box.params.Autonomous && box.registry != nil {
		n := params.Node
		n.Address = address
		if box.info == nil {
			box.info = new(pb.Info)
			box.info.Id = box.Name()
			box.info.Type = params.ServiceType
			if box.info.Meta == nil {
				box.info.Meta = map[string]string{}
			}
		}
		box.info.Nodes = append(box.info.Nodes, n)

		// gt.RegistryID, err = box.registry.RegisterService(info, pb.ActionOnRegisterExistingService_AddNodes|pb.ActionOnRegisterExistingService_UpdateExisting)
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
		proxyAuthorizationHeader := r.Header.Get("")
		if proxyAuthorizationHeader != "" {
			decodedBytes, err := base64.StdEncoding.DecodeString(proxyAuthorizationHeader)
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
	verifier authpb.TokenVerifier
}

func (atv *authorizationBearer) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorizationHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authorizationHeader, "Bearer ") {
			accessToken := strings.TrimLeft(authorizationHeader, "Bearer ")

			strJWT, err := authpb.ExtractJwtFromAccessToken("", accessToken, atv.codecs...)
			if err != nil {
				//log.Error("could not extract jwt from access token", log.Err(err))
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
				//log.Error("could not verify JWT", log.Err(err), log.Field("jwt", strJWT))
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			if state != authpb.JWTState_VALID {
				//log.Info("invalid JWT", log.Field("jwt", strJWT))
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

type authorizationJWT struct {
	verifier authpb.TokenVerifier
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
				info, err := reg.FirstOfType(pb.Type_Auth)
				if err != nil {
					log.Error("could not find authentication server in registry")
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				for _, node := range info.Nodes {
					if node.Protocol == pb.Protocol_Http {
						endpoint := fmt.Sprintf("https://%s/token/introspect", node.Address)
						client := http.Client{}
						if node.Security != pb.Security_None {
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
						credentialsPart := strings.Split(box.params.CACredentials, ":")
						req.SetBasicAuth(credentialsPart[0], credentialsPart[1])

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

						var jwt authpb.JWT
						err = json.NewDecoder(rsp.Body).Decode(&jwt)
						if err != nil {
							log.Error("could not read introspection body response", log.Err(err))
							w.WriteHeader(http.StatusForbidden)
							return
						}

						ctx := r.Context()
						ctx = authpb.ContextWithToken(ctx, &jwt)
						r = r.WithContext(ctx)
					}
				}
			} else {
				t, err := authpb.ParseJWT(strJWT)
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
		}
		next.ServeHTTP(w, r)
	})
}

func JWT(verifier authpb.TokenVerifier) *authorizationJWT {
	return &authorizationJWT{
		verifier: verifier,
	}
}
