package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_zap "github.com/grpc-ecosystem/go-grpc-middleware/logging/zap"
	grpc_opentracing "github.com/grpc-ecosystem/go-grpc-middleware/tracing/opentracing"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	crypto2 "github.com/omecodes/common/crypto"
	"github.com/omecodes/common/errors"
	"github.com/omecodes/common/grpc-authentication"
	"github.com/omecodes/common/log"
	"github.com/omecodes/common/ports"
	pb "github.com/omecodes/common/proto/service"
	"github.com/omecodes/service/interceptors"
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

func (box *Box) CAClientAuthentication() credentials.PerRPCCredentials {
	if box.caClientAuthentication == nil {
		parts := strings.Split(box.params.CACredentials, ":")
		box.caClientAuthentication = ga.NewGRPCBasic(parts[0], parts[1])
	}
	return box.caClientAuthentication
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
				runtime.WithProtoErrorHandler(box.handlerError),
			)
			var opts []grpc.DialOption

			if node.Security == pb.Security_None {
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
				srv.Handler = mux
			}

			gt := &httpNode{}
			gt.Server = srv
			gt.Address = address
			if node.Security == pb.Security_None {
				gt.Scheme = "http"
			} else {
				gt.Scheme = "https"
			}

			gt.Name = params.NodeName
			box.httpNodes[params.NodeName] = gt
			go func() {
				err := srv.Serve(listener)
				if err != http.ErrServerClosed {
					log.Error("http server stopped", err)
				}

				if box.info != nil {
					var newNodeList []*pb.Node
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
						box.info = &pb.Info{}
						box.info.Id = box.Name()
						box.info.Type = info.Type
					}

					n := &pb.Node{}
					n.Id = params.NodeName
					n.Address = address
					n.Protocol = pb.Protocol_Http
					n.Security = params.Security
					n.Meta = params.Meta
					box.info.Nodes = append(box.info.Nodes, n)

					err = box.registry.RegisterService(box.info)
					if err != nil {
						log.Error("could not register service", err)
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
			runtime.WithProtoErrorHandler(box.handlerError),
		)
		var opts []grpc.DialOption

		if node.Security == pb.Security_None {
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
			srv.Handler = mux
		}

		gt := &httpNode{}
		gt.Server = srv
		gt.Address = address
		gt.Scheme = "https"

		gt.Name = params.NodeName
		box.httpNodes[params.NodeName] = gt
		go func() {
			err := srv.ListenAndServeTLS("", "")
			if err != http.ErrServerClosed {
				log.Fatal("failed to start server", err)
			}

			if box.info != nil {
				var newNodeList []*pb.Node
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
				log.Error("failed to run acme server", err)
			}
		}()

		if params.ForceRegister || !box.params.CA && !box.params.Autonomous {
			if box.registry != nil {
				if box.info == nil {
					box.info = &pb.Info{}
					box.info.Id = box.Name()
					box.info.Type = info.Type
				}

				n := &pb.Node{}
				n.Id = params.NodeName
				n.Address = address
				n.Protocol = pb.Protocol_Http
				n.Security = pb.Security_ACME
				n.Meta = params.Meta
				box.info.Nodes = append(box.info.Nodes, n)

				err = box.registry.RegisterService(box.info)
				if err != nil {
					log.Error("could not register service", err)
				}
			}
		}
		return nil
	}

	log.Error("could not run gateway", errors.NotFound, log.Field("for", params.TargetNodeName))
	return errors.NotFound
}

func (box *Box) StartGrpcNode(params *GrpcNodeParams) error {
	box.serverMutex.Lock()
	defer box.serverMutex.Unlock()

	listener, err := box.listen(params.Port, pb.Security_MutualTLS, params.Tls)
	if err != nil {
		return err
	}

	address := listener.Addr().String()
	if box.params.Domain != "" {
		address = strings.Replace(address, box.params.Ip, box.params.Domain, 1)
	}

	log.Info("starting gRPC server", log.Field("service", params.Node.Id), log.Field("address", address))
	var opts []grpc.ServerOption

	defaultInterceptor := interceptors.Default(
		interceptors.ProxyBasic(),
		interceptors.Jwt(box.JwtVerifyFunc),
	)

	streamInterceptors := append([]grpc.StreamServerInterceptor{},
		grpc_opentracing.StreamServerInterceptor(),
		defaultInterceptor.InterceptStream,
	)

	unaryInterceptors := append([]grpc.UnaryServerInterceptor{},
		grpc_opentracing.UnaryServerInterceptor(),
		defaultInterceptor.InterceptUnary,
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
			log.Error("grpc server stopped", err)
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
	}()

	if params.ForceRegister || !box.params.CA && !box.params.Autonomous && params.Node != nil && box.registry != nil {
		if box.info == nil {
			box.info = &pb.Info{}
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
			log.Error("could not register service", err, log.Field("name", params.Node.Id))
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
			log.Error("could not deregister service", err, log.Field("name", name))
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
				log.Error("could not de register service", err, log.Field("name", box.Name()))
			}
		}
	}
	box.gRPCNodes = map[string]*gPRCNode{}
	return nil
}

func (box *Box) StartCAService(credentialsVerifier ga.ProxyCredentialsVerifyFunc) error {
	box.serverMutex.Lock()
	defer box.serverMutex.Unlock()

	var tc *tls.Config
	certPEMBytes, _ := crypto2.PEMEncodeCertificate(box.cert)
	keyPEMBytes, _ := crypto2.PEMEncodeKey(box.privateKey)
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
		log.Error("could not load TLS configs", err)
		return err
	}

	address := fmt.Sprintf("%s:%d", box.Domain(), ports.CA)

	listener, err := tls.Listen("tcp", address, tc)
	if err != nil {
		return err
	}

	log.Info("starting gRPC server", log.Field("service", "CA"), log.Field("at", address))
	var opts []grpc.ServerOption

	defaultInterceptor := interceptors.Default(
		interceptors.ProxyBasic(),
	)

	logger, _ := zap.NewProduction()
	chainUnaryInterceptor := grpc_middleware.ChainUnaryServer(
		defaultInterceptor.InterceptUnary,
		grpc_opentracing.UnaryServerInterceptor(),
		grpc_zap.UnaryServerInterceptor(logger),
	)

	opts = append(opts, grpc.UnaryInterceptor(chainUnaryInterceptor))
	srv := grpc.NewServer(opts...)
	pb.RegisterCSRServer(srv, &csrServerHandler{
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
