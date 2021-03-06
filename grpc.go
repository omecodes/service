package service

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/google/uuid"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_opentracing "github.com/grpc-ecosystem/go-grpc-middleware/tracing/opentracing"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/omecodes/common/errors"
	"github.com/omecodes/common/httpx"
	"github.com/omecodes/common/utils/log"
	"github.com/omecodes/libome"
	"github.com/omecodes/libome/logs"
	"golang.org/x/crypto/acme/autocert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"net"
	"net/http"
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

		box.Options.override(options.boxOptions...)

		info, err := box.registry.GetService(params.ServiceName)
		if err != nil {
			return err
		}

		var listener net.Listener
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

		for _, node := range info.Nodes {
			if node.Id != params.TargetNodeName {
				continue
			}

			address := listener.Addr().String()

			if box.Options.netMainDomain != "" {
				address = strings.Replace(address, box.Options.netIP, box.Options.netMainDomain, 1)
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
				tc, err := box.ClientMutualTLS()
				if err != nil {
					return err
				}
				opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tc)))
			}

			err = params.Binder(ctx, mux, *grpcServerEndpoint, opts)
			if err != nil {
				return err
			}

			logs.Info("starting HTTP server", logs.Details("service-gateway", params.NodeName), logs.Details("for", params.TargetNodeName), logs.Details("address", address))
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
					logs.Error("http server stopped", logs.Err(err))
				}

				if info, deleted := box.DeleteNode(params.ServiceType, params.ServiceID, params.NodeName); deleted {
					_ = box.registry.RegisterService(info)
				}
			}()

			if options.register {
				reg, err := box.Options.Registry()
				if err != nil {
					return err
				}
				n := &ome.Node{
					Id:       params.NodeName,
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
	}
	return errors.New("matching gRPC service not found")
}

func (box *Box) StartPublicNodeGateway(params *PublicNodeGatewayParams, nOpts ...NodeOption) error {

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
			tc, err := box.ClientMutualTLS()
			if err != nil {
				return err
			}
			opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tc)))
		}

		err = params.Binder(ctx, mux, *grpcServerEndpoint, opts)
		if err != nil {
			return err
		}

		address := fmt.Sprintf("%s:443", box.Host())

		logs.Info("starting HTTP server", logs.Details("service-gateway", params.NodeName), logs.Details("for", params.TargetNodeName), logs.Details("address", address))
		srv := &http.Server{
			Addr:         address,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
			IdleTimeout:  120 * time.Second,
			TLSConfig: &tls.Config{
				GetCertificate: certManager.GetCertificate,
			},
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
				logs.Fatal("failed to start server", logs.Err(err))
			}

			if info, deleted := box.DeleteNode(params.ServiceType, params.ServiceID, params.NodeName); deleted {
				_ = box.registry.RegisterService(info)
			}
		}()

		if options.register {
			reg, err := box.Options.Registry()
			if err != nil {
				return err
			}
			n := &ome.Node{
				Id:       params.NodeName,
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

	logs.Error("could not run gateway", logs.Details("for", params.TargetNodeName), logs.Err(errors.NotFound))
	return errors.NotFound
}

func (box *Box) StartNode(params *NodeParams, nOpts ...NodeOption) error {
	box.serverMutex.Lock()
	defer box.serverMutex.Unlock()

	options := new(nodeOptions)
	for _, o := range nOpts {
		o(options)
	}

	if params.Name == "" {
		params.Name = uuid.New().String()
	}

	box.Options.override(options.boxOptions...)

	listener, _, err := box.Options.listen(options.port, ome.Security_MutualTls)
	if err != nil {
		return err
	}

	address := listener.Addr().String()
	if box.Options.netMainDomain != "" {
		address = strings.Replace(address, box.Options.netIP, box.Options.netMainDomain, 1)
	}

	logs.Info("starting gRPC server", logs.Details("service", params.Name), logs.Details("address", address))
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
	rs.Secure = true

	rs.Name = params.Name
	box.gRPCNodes[params.Name] = rs

	params.RegisterHandlerFunc(srv)
	go func() {
		err := srv.Serve(listener)
		if err != grpc.ErrServerStopped {
			logs.Error("grpc server stopped", logs.Err(err))
		}

		if info, deleted := box.DeleteNode(params.ServiceType, params.ServiceID, params.Name); deleted {
			_ = box.registry.RegisterService(info)
		}
	}()

	if options.register {
		reg, err := box.Options.Registry()
		if err != nil {
			return err
		}

		n := &ome.Node{
			Id:       params.Name,
			Protocol: ome.Protocol_Grpc,
			Address:  address,
			Security: ome.Security_MutualTls,
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

func (box *Box) StopNode(name string) {
	box.serverMutex.Lock()
	defer box.serverMutex.Unlock()
	rs := box.gRPCNodes[name]
	delete(box.gRPCNodes, name)

	if rs != nil && box.registry != nil {
		err := box.registry.DeregisterService(name)
		if err != nil {
			logs.Error("could not deregister service", logs.Err(err), logs.Details("name", name))
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
			logs.Error("could not de register service", logs.Err(err), logs.Details("name", box.Name()))
		}
	}
	box.gRPCNodes = map[string]*gPRCNode{}
	return nil
}

func (box *Box) handlerError(ctx context.Context, mux *runtime.ServeMux, m runtime.Marshaler, w http.ResponseWriter, r *http.Request, err error) {
	logs.Info("caught error", logs.Details("err", err))
	st, ok := status.FromError(err)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(errors.HttpStatus(errors.New(st.Message())))
}
