package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_zap "github.com/grpc-ecosystem/go-grpc-middleware/logging/zap"
	grpc_opentracing "github.com/grpc-ecosystem/go-grpc-middleware/tracing/opentracing"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/omecodes/common/errors"
	"github.com/omecodes/common/httpx"
	"github.com/omecodes/common/utils/log"
	"github.com/omecodes/libome"
	"github.com/omecodes/libome/crypt"
	"github.com/omecodes/libome/ports"
	"go.uber.org/zap"
	"golang.org/x/crypto/acme/autocert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"net/http"
	"path/filepath"
	"strings"
	"time"
)

type Mapper func(context.Context, *runtime.ServeMux, string, []grpc.DialOption) error

type MuxWrapper func(mux *runtime.ServeMux) http.Handler

func (box *Box) OmeBasicClientCredentials() credentials.PerRPCCredentials {
	if box.caClientAuthentication == nil {
		parts := strings.Split(box.params.CACredentials, ":")
		box.caClientAuthentication = ome.NewGRPCBasic(parts[0], parts[1])
	}
	return box.caClientAuthentication
}

func (box *Box) OmeProxyBasicClientCredentials() credentials.PerRPCCredentials {
	parts := strings.Split(box.params.CACredentials, ":")
	return ome.NewGRPCProxy(parts[0], parts[1])
}

func (box *Box) CAClientTransportCredentials() credentials.TransportCredentials {
	return box.caGRPCTransportCredentials
}

func (box *Box) StartGatewayGrpcMappingNode(params *GatewayGrpcMappingParams) error {
	if box.registry != nil && !box.params.Autonomous {
		box.serverMutex.Lock()
		defer box.serverMutex.Unlock()

		info, err := box.registry.GetService(params.ServiceName)
		if err != nil {
			return err
		}

		listener, err := box.listen(params.Port, params.Security, params.Tls)
		if err != nil {
			return err
		}

		for _, node := range info.Nodes {
			if node.Id != params.TargetNodeName {
				continue
			}

			address := listener.Addr().String()
			if box.params.Domain != "" {
				address = strings.Replace(address, box.params.Ip, box.params.Domain, 1)
			}

			endpoint := fmt.Sprintf("%s-gateway-endpoint", params.TargetNodeName)
			grpcServerEndpoint := flag.String(endpoint, node.Address, "gRPC server endpoint")
			ctx := context.Background()
			mux := runtime.NewServeMux(
				runtime.WithErrorHandler(box.handlerError),
			)
			var opts []grpc.DialOption

			if node.Security == ome.Security_Insecure {
				opts = append(opts, grpc.WithInsecure())
			} else {
				opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(box.ClientMutualTLS())))
			}

			err = params.Binder(ctx, mux, *grpcServerEndpoint, opts)
			if err != nil {
				return err
			}

			log.Info("starting HTTP server", log.Field("service-gateway", params.NodeName), log.Field("for", params.TargetNodeName), log.Field("address", address))
			srv := &http.Server{Addr: address}

			if params.MuxWrapper != nil {
				srv.Handler = params.MuxWrapper(mux)
			} else {
				srv.Handler = httpx.Logger(params.NodeName).Handle(mux)
			}
			srv.Handler = httpx.ContextUpdater(func(ctx context.Context) context.Context {
				return ContextWithBox(ctx, box)
			}).Handle(srv.Handler)

			gt := &httpNode{}
			gt.Server = srv
			gt.Address = address
			if node.Security == ome.Security_Insecure {
				gt.Scheme = "http"
			} else {
				gt.Scheme = "https"
			}

			gt.Name = params.NodeName
			box.httpNodes[params.NodeName] = gt
			go func() {
				err := srv.Serve(listener)
				if err != http.ErrServerClosed {
					log.Error("http server stopped", log.Err(err))
				}

				if box.info != nil {
					var newNodeList []*ome.Node
					for _, node := range box.info.Nodes {
						if node.Id != params.NodeName {
							newNodeList = append(newNodeList, node)
						}
					}
					box.info.Nodes = newNodeList
					_ = box.registry.RegisterService(box.info)
				}
			}()

			if params.ForceRegister || !box.params.CA && !box.params.Autonomous {
				if box.registry != nil {
					if box.info == nil {
						box.info = &ome.ServiceInfo{}
						box.info.Id = box.Name()
						box.info.Type = info.Type
					}

					n := &ome.Node{}
					n.Id = params.NodeName
					n.Address = address
					n.Protocol = ome.Protocol_Http
					n.Security = params.Security
					n.Meta = params.Meta
					box.info.Nodes = append(box.info.Nodes, n)

					err = box.registry.RegisterService(box.info)
					if err != nil {
						log.Error("could not register service", log.Err(err))
					}
				}
			}
			return nil
		}
	}
	return errors.New("matching gRPC service not found")
}

func (box *Box) StartAcmeServiceGatewayMapping(params *ACMEServiceGatewayParams) error {

	box.serverMutex.Lock()
	defer box.serverMutex.Unlock()

	info, err := box.registry.GetService(params.ServiceName)
	if err != nil {
		return err
	}

	for _, node := range info.Nodes {
		if node.Id != params.TargetNodeName {
			continue
		}

		cacheDir := filepath.Dir(box.CertificateFilename())
		hostPolicy := func(ctx context.Context, host string) error {
			// Note: change to your real domain
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

		endpoint := fmt.Sprintf("%s-gateway-endpoint", params.TargetNodeName)
		grpcServerEndpoint := flag.String(endpoint, node.Address, "gRPC server endpoint")
		ctx := context.Background()
		mux := runtime.NewServeMux(
			runtime.WithErrorHandler(box.handlerError),
		)
		var opts []grpc.DialOption

		if node.Security == ome.Security_Insecure {
			opts = append(opts, grpc.WithInsecure())
		} else {
			opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(box.ClientMutualTLS())))
		}

		err = params.Binder(ctx, mux, *grpcServerEndpoint, opts)
		if err != nil {
			return err
		}

		address := fmt.Sprintf("%s:443", box.Host())

		log.Info("starting HTTP server", log.Field("service-gateway", params.NodeName), log.Field("for", params.TargetNodeName), log.Field("address", address))
		srv := &http.Server{
			Addr:         address,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
			IdleTimeout:  120 * time.Second,
			TLSConfig:    &tls.Config{GetCertificate: man.GetCertificate},
		}

		if params.MuxWrapper != nil {
			srv.Handler = params.MuxWrapper(mux)
		} else {
			srv.Handler = httpx.Logger(params.NodeName).Handle(mux)
		}

		srv.Handler = httpx.ContextUpdater(func(ctx context.Context) context.Context {
			return ContextWithBox(ctx, box)
		}).Handle(srv.Handler)

		gt := &httpNode{}
		gt.Server = srv
		gt.Address = address
		gt.Scheme = "https"

		gt.Name = params.NodeName
		box.httpNodes[params.NodeName] = gt
		go func() {
			err := srv.ListenAndServeTLS("", "")
			if err != http.ErrServerClosed {
				log.Fatal("failed to start server", log.Err(err))
			}

			if box.info != nil {
				var newNodeList []*ome.Node
				for _, node := range box.info.Nodes {
					if node.Id != params.NodeName {
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
		}()

		if params.ForceRegister || !box.params.CA && !box.params.Autonomous {
			if box.registry != nil {
				if box.info == nil {
					box.info = &ome.ServiceInfo{}
					box.info.Id = box.Name()
					box.info.Type = info.Type
				}

				n := &ome.Node{}
				n.Id = params.NodeName
				n.Address = address
				n.Protocol = ome.Protocol_Http
				n.Security = ome.Security_Acme
				n.Meta = params.Meta
				box.info.Nodes = append(box.info.Nodes, n)

				err = box.registry.RegisterService(box.info)
				if err != nil {
					log.Error("could not register service", log.Err(err))
				}
			}
		}
		return nil
	}

	log.Error("could not run gateway", log.Field("for", params.TargetNodeName), log.Err(errors.NotFound))
	return errors.NotFound
}

func (box *Box) StartGrpcNode(params *GrpcNodeParams) error {
	box.serverMutex.Lock()
	defer box.serverMutex.Unlock()

	listener, err := box.listen(params.Port, ome.Security_MutualTls, params.Tls)
	if err != nil {
		return err
	}

	address := listener.Addr().String()
	if box.params.Domain != "" {
		address = strings.Replace(address, box.params.Ip, box.params.Domain, 1)
	}

	log.Info("starting gRPC server", log.Field("service", params.Node.Id), log.Field("address", address))
	var opts []grpc.ServerOption

	interceptorChain := NewInterceptorsChain(
		InterceptorFunc(
			func(ctx context.Context) (context.Context, error) {
				return ContextWithBox(ctx, box), nil
			}),
		NewProxyBasicInterceptor(),
		NewJwtVerifierInterceptor(box.JwtVerifyFunc),
	)

	streamInterceptors := append([]grpc.StreamServerInterceptor{},
		grpc_opentracing.StreamServerInterceptor(),
		interceptorChain.InterceptStream,
	)

	unaryInterceptors := append([]grpc.UnaryServerInterceptor{},
		grpc_opentracing.UnaryServerInterceptor(),
		interceptorChain.InterceptUnary,
	)

	if params.Interceptor != nil {
		streamInterceptors = append(streamInterceptors, params.Interceptor.InterceptStream)
		unaryInterceptors = append(unaryInterceptors, params.Interceptor.InterceptUnary)
	}

	chainUnaryInterceptor := grpc_middleware.ChainUnaryServer(unaryInterceptors...)
	chainStreamInterceptor := grpc_middleware.ChainStreamServer(streamInterceptors...)
	opts = append(opts,
		grpc.StreamInterceptor(chainStreamInterceptor),
		grpc.UnaryInterceptor(chainUnaryInterceptor))

	srv := grpc.NewServer(opts...)
	rs := new(gPRCNode)
	rs.Address = address
	rs.Server = srv
	rs.Secure = params.Tls != nil

	rs.Name = params.Node.Id
	box.gRPCNodes[params.Node.Id] = rs

	params.RegisterHandlerFunc(srv)
	go func() {
		err := srv.Serve(listener)
		if err != grpc.ErrServerStopped {
			log.Error("grpc server stopped", log.Err(err))
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
	}()

	if params.ForceRegister || !box.params.CA && !box.params.Autonomous && params.Node != nil && box.registry != nil {
		if box.info == nil {
			box.info = &ome.ServiceInfo{}
			box.info.Id = box.Name()
			box.info.Type = params.ServiceType
			if box.info.Meta == nil {
				box.info.Meta = map[string]string{}
			}
			for name, meta := range params.Meta {
				box.info.Meta[name] = meta
			}
		}

		params.Node.Address = address
		box.info.Nodes = append(box.info.Nodes, params.Node)

		err = box.registry.RegisterService(box.info)
		if err != nil {
			log.Error("could not register service", log.Err(err), log.Field("name", params.Node.Id))
		}
	}
	return nil
}

func (box *Box) StopService(name string) {
	box.serverMutex.Lock()
	defer box.serverMutex.Unlock()
	rs := box.gRPCNodes[name]
	delete(box.gRPCNodes, name)
	if !box.params.Autonomous && rs != nil && box.registry != nil {
		err := box.registry.DeregisterService(name)
		if err != nil {
			log.Error("could not deregister service", log.Err(err), log.Field("name", name))
		}
		rs.Stop()
	}
}

func (box *Box) stopServices() error {
	box.serverMutex.Lock()
	defer box.serverMutex.Unlock()

	if box.registry != nil {
		for _, rs := range box.gRPCNodes {
			rs.Stop()
		}

		if !box.params.Autonomous {
			err := box.registry.DeregisterService(box.Name(), box.Name())
			if err != nil {
				log.Error("could not de register service", log.Err(err), log.Field("name", box.Name()))
			}
		}
	}
	box.gRPCNodes = map[string]*gPRCNode{}
	return nil
}

func (box *Box) StartCAService(credentialsVerifier CredentialsVerifyFunc) error {
	box.serverMutex.Lock()
	defer box.serverMutex.Unlock()

	var tc *tls.Config
	certPEMBytes, _ := crypt.PEMEncodeCertificate(box.cert)
	keyPEMBytes, _ := crypt.PEMEncodeKey(box.privateKey)
	tlsCert, err := tls.X509KeyPair(certPEMBytes, keyPEMBytes)
	if err == nil {
		clientCAs := x509.NewCertPool()
		clientCAs.AddCert(box.cert)
		tc = &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			ClientCAs:    clientCAs,
			ClientAuth:   tls.VerifyClientCertIfGiven,
		}
	} else {
		log.Error("could not load TLS configs", log.Err(err))
		return err
	}

	address := fmt.Sprintf("%s:%d", box.Domain(), ports.CA)

	listener, err := tls.Listen("tcp", address, tc)
	if err != nil {
		return err
	}

	log.Info("starting gRPC server", log.Field("service", "CA"), log.Field("at", address))
	var opts []grpc.ServerOption

	defaultInterceptor := NewInterceptorsChain(
		NewProxyBasicInterceptor(),
	)

	logger, _ := zap.NewProduction()
	chainUnaryInterceptor := grpc_middleware.ChainUnaryServer(
		defaultInterceptor.InterceptUnary,
		grpc_opentracing.UnaryServerInterceptor(),
		grpc_zap.UnaryServerInterceptor(logger),
	)

	opts = append(opts, grpc.UnaryInterceptor(chainUnaryInterceptor))
	srv := grpc.NewServer(opts...)
	ome.RegisterCSRServer(srv, &csrServerHandler{
		credentialsVerifyFunc: credentialsVerifier,
		PrivateKey:            box.privateKey,
		Certificate:           box.cert,
	})

	rs := new(gPRCNode)
	rs.Address = address
	rs.Server = srv
	rs.Secure = true
	box.gRPCNodes["ca"] = rs

	go srv.Serve(listener)
	return nil
}

func (box *Box) handlerError(ctx context.Context, mux *runtime.ServeMux, m runtime.Marshaler, w http.ResponseWriter, r *http.Request, err error) {
	log.Info("caught error", log.Field("err", err))
	st, ok := status.FromError(err)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(errors.HttpStatus(errors.New(st.Message())))
}
