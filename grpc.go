package service

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_opentracing "github.com/grpc-ecosystem/go-grpc-middleware/tracing/opentracing"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/omecodes/common/errors"
	"github.com/omecodes/common/httpx"
	"github.com/omecodes/common/utils/log"
	"github.com/omecodes/discover"
	"github.com/omecodes/libome"
	"github.com/omecodes/libome/ports"
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

func (box *Box) StartNodeGateway(params *NodeGatewayParams, nOpts ...NodeOption) error {
	if box.registry != nil {
		box.serverMutex.Lock()
		defer box.serverMutex.Unlock()

		options := new(nodeOptions)
		for _, o := range nOpts {
			o(options)
		}

		info, err := box.registry.GetService(params.ServiceName)
		if err != nil {
			return err
		}

		listener, err := box.listen(options.port, params.Security, options.tlsConfig)
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

			if options.register {
				box.ConnectToRegistry()

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
					n.Meta = options.md
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

func (box *Box) StartAcmeNodeGateway(params *ACMENodeGatewayParams, nOpts ...NodeOption) error {

	box.serverMutex.Lock()
	defer box.serverMutex.Unlock()

	options := new(nodeOptions)
	for _, o := range nOpts {
		o(options)
	}

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

		if options.register {
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
				n.Meta = options.md
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

func (box *Box) StartNode(params *NodeParams, nOpts ...NodeOption) error {
	box.serverMutex.Lock()
	defer box.serverMutex.Unlock()

	options := new(nodeOptions)
	for _, o := range nOpts {
		o(options)
	}

	listener, err := box.listen(options.port, ome.Security_MutualTls, options.tlsConfig)
	if err != nil {
		return err
	}

	address := listener.Addr().String()
	if box.params.Domain != "" {
		address = strings.Replace(address, box.params.Ip, box.params.Domain, 1)
	}

	log.Info("starting gRPC server", log.Field("service", params.Node.Id), log.Field("address", address))
	var opts []grpc.ServerOption

	mergedInterceptors := ome.NewGrpcContextInterceptor(options.interceptors...)
	streamInterceptors := append([]grpc.StreamServerInterceptor{},
		grpc_opentracing.StreamServerInterceptor(),
		mergedInterceptors.StreamUpdate,
	)
	unaryInterceptors := append([]grpc.UnaryServerInterceptor{},
		grpc_opentracing.UnaryServerInterceptor(),
		mergedInterceptors.UnaryUpdate,
	)

	chainUnaryInterceptor := grpc_middleware.ChainUnaryServer(unaryInterceptors...)
	chainStreamInterceptor := grpc_middleware.ChainStreamServer(streamInterceptors...)
	opts = append(opts,
		grpc.StreamInterceptor(chainStreamInterceptor),
		grpc.UnaryInterceptor(chainUnaryInterceptor))

	srv := grpc.NewServer(opts...)
	rs := new(gPRCNode)
	rs.Address = address
	rs.Server = srv
	rs.Secure = options.tlsConfig != nil

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

	if options.register || params.Node != nil {
		box.ConnectToRegistry()

		if box.info == nil {
			box.info = &ome.ServiceInfo{}
			box.info.Id = box.Name()
			box.info.Type = params.ServiceType
			if box.info.Meta == nil {
				box.info.Meta = map[string]string{}
			}
			for name, meta := range options.md {
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

func (box *Box) StartRegistry() (err error) {
	if box.params.RegistryAddress == "" {
		box.params.RegistryAddress = fmt.Sprintf("%s:%d", box.Host(), ports.Discover)

	} else {
		parts := strings.Split(box.params.RegistryAddress, ":")
		if len(parts) != 2 {
			if len(parts) == 1 {
				box.params.RegistryAddress = fmt.Sprintf("%s:%d", box.params.RegistryAddress, ports.Discover)
			}
			return errors.New("malformed registry address. Should be like HOST:PORT")
		}
	}

	dc := &discover.ServerConfig{
		Name:                 box.params.Name,
		StoreDir:             box.Dir(),
		BindAddress:          box.params.RegistryAddress,
		CertFilename:         box.CertificateFilename(),
		KeyFilename:          box.KeyFilename(),
		ClientCACertFilename: box.params.CACertPath,
	}
	box.registry, err = discover.Serve(dc)
	if err != nil {
		log.Error("impossible to run discovery server", log.Err(err))
	}

	return nil
}

func (box *Box) StopRegistry() error {
	if box.registry == nil {
		return nil
	}

	if stopper, ok := box.registry.(interface {
		Stop() error
	}); ok {
		return stopper.Stop()
	}
	return nil
}

func (box *Box) ConnectToRegistry() {
	box.Registry()
}

func (box *Box) StopNode(name string) {
	box.serverMutex.Lock()
	defer box.serverMutex.Unlock()
	rs := box.gRPCNodes[name]
	delete(box.gRPCNodes, name)

	if rs != nil && box.registry != nil {
		err := box.registry.DeregisterService(name)
		if err != nil {
			log.Error("could not deregister service", log.Err(err), log.Field("name", name))
		}
		rs.Stop()
	}
}

func (box *Box) stopNodes() error {
	box.serverMutex.Lock()
	defer box.serverMutex.Unlock()

	if box.registry != nil {
		for _, rs := range box.gRPCNodes {
			rs.Stop()
		}

		err := box.registry.DeregisterService(box.Name(), box.Name())
		if err != nil {
			log.Error("could not de register service", log.Err(err), log.Field("name", box.Name()))
		}
	}
	box.gRPCNodes = map[string]*gPRCNode{}
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
