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
	crypto2 "github.com/zoenion/common/crypto"
	"github.com/zoenion/common/errors"
	"github.com/zoenion/common/grpc-authentication"
	authpb "github.com/zoenion/common/proto/auth"
	"github.com/zoenion/service/interceptors"
	pb "github.com/zoenion/service/proto"
	"github.com/zoenion/service/server"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"log"
	"net/http"
)

func (box *Box) CAClientAuthentication() credentials.PerRPCCredentials {
	return box.caClientAuthentication
}

func (box *Box) CAClientTransportCredentials() credentials.TransportCredentials {
	return box.caGRPCTransportCredentials
}

func (box *Box) StartGatewayGRPCMapping(params *server.GatewayServiceMappingParams) error {
	if box.registry != nil && !box.params.Autonomous {
		box.serverMutex.Lock()
		defer box.serverMutex.Unlock()

		info, err := box.registry.GetService(box.params.Namespace + "." + params.ServiceName)
		if err != nil {
			return err
		}

		listener, err := box.listen(params.Port, params.Security, params.Tls)
		if err != nil {
			return err
		}

		for _, node := range info.Nodes {
			if node.Name != params.TargetNodeName {
				continue
			}

			address := listener.Addr().String()
			grpcServerEndpoint := flag.String("grpc-server-endpoint", node.Address, "gRPC server endpoint")
			ctx := context.Background()
			mux := runtime.NewServeMux()
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

			log.Printf("starting %s.HTTP at %s", params.ServiceName, address)
			srv := &http.Server{
				Addr:    address,
				Handler: mux,
			}
			gt := &server.Gateway{}
			gt.Server = srv
			gt.Address = address
			if params.Tls != nil {
				gt.Scheme = "https"
			} else {
				gt.Scheme = "http"
			}

			box.gateways[params.ServiceName] = gt
			go srv.Serve(listener)

			if box.registry != nil {
				info := &pb.Info{}
				info.Namespace = box.params.Namespace
				info.Name = box.Name()
				n := &pb.Node{}
				n.Name = params.NodeName
				n.Address = address
				n.Protocol = pb.Protocol_Http
				n.Security = params.Security
				info.Nodes = []*pb.Node{n}

				gt.RegistryID, err = box.registry.RegisterService(info, pb.ActionOnRegisterExistingService_AddNodes|pb.ActionOnRegisterExistingService_UpdateExisting)
				if err != nil {
					log.Println("could not register service")
				}
			}
			return nil
		}
	}
	return errors.New("matching gRPC service not found")
}

func (box *Box) StartService(params *server.ServiceParams) error {
	box.serverMutex.Lock()
	defer box.serverMutex.Unlock()

	listener, err := box.listen(params.Port, pb.Security_MutualTLS, params.Tls)
	if err != nil {
		return err
	}
	address := listener.Addr().String()

	log.Printf("starting %s.gRPC at %s", params.Node.Name, address)
	var opts []grpc.ServerOption

	defaultInterceptor := interceptors.Default(
		interceptors.NewGateway(""),
		interceptors.NewProxyBasic(),
		interceptors.NewBasic(),
		interceptors.NewJwt(box.JwtVerifyFunc),
	)

	var chainStreamInterceptor grpc.StreamServerInterceptor
	var chainUnaryInterceptor grpc.UnaryServerInterceptor
	logger, _ := zap.NewProduction()

	if params.Interceptor != nil {
		chainStreamInterceptor = grpc_middleware.ChainStreamServer(
			defaultInterceptor.InterceptStream,
			grpc_opentracing.StreamServerInterceptor(),
			grpc_zap.StreamServerInterceptor(logger),
			params.Interceptor.InterceptStream,
		)
		chainUnaryInterceptor = grpc_middleware.ChainUnaryServer(
			defaultInterceptor.InterceptUnary,
			grpc_opentracing.UnaryServerInterceptor(),
			grpc_zap.UnaryServerInterceptor(logger),
			params.Interceptor.InterceptUnary,
		)
	} else {
		chainStreamInterceptor = grpc_middleware.ChainStreamServer(defaultInterceptor.InterceptStream)
		chainUnaryInterceptor = grpc_middleware.ChainUnaryServer(defaultInterceptor.InterceptUnary)
	}

	if params.Interceptor != nil {
	}
	opts = append(opts, grpc.StreamInterceptor(chainStreamInterceptor), grpc.UnaryInterceptor(chainUnaryInterceptor))

	srv := grpc.NewServer(opts...)
	rs := new(server.Service)
	rs.Address = address
	rs.Server = srv
	rs.Secure = params.Tls != nil

	box.services[params.Node.Name] = rs

	params.RegisterHandlerFunc(srv)
	go srv.Serve(listener)

	if !box.params.Autonomous && params.Node != nil && box.registry != nil {
		info := &pb.Info{}
		info.Namespace = box.params.Namespace
		info.Name = box.Name()
		info.Label = box.Name()
		info.Type = params.ServiceType
		info.Meta = params.Meta

		params.Node.Address = address
		info.Nodes = []*pb.Node{params.Node}

		rs.RegistryID, err = box.registry.RegisterService(info, pb.ActionOnRegisterExistingService_AddNodes|pb.ActionOnRegisterExistingService_UpdateExisting)
		if err != nil {
			log.Println("could not register service")
		}
	}
	return nil
}

func (box *Box) StopService(name string) {
	box.serverMutex.Lock()
	defer box.serverMutex.Unlock()
	rs := box.services[name]
	delete(box.services, name)
	if !box.params.Autonomous && rs != nil && box.registry != nil {
		err := box.registry.DeregisterService(rs.RegistryID)
		if err != nil {
			log.Println("could not deregister service:", name)
		}
		rs.Stop()
	}
}

func (box *Box) stopServices() error {
	box.serverMutex.Lock()
	defer box.serverMutex.Unlock()
	if box.registry != nil {
		for name, rs := range box.services {
			rs.Stop()
			if !box.params.Autonomous && rs.RegistryID != "" {
				err := box.registry.DeregisterService(rs.RegistryID)
				if err != nil {
					log.Println("could not deregister service:", name)
				}
			}
		}
	}
	box.services = map[string]*server.Service{}
	return nil
}

func (box *Box) startCA(pc *ga.ProxyCredentials) error {
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
		log.Println("could not load TLS configs")
		return err
	}

	address := fmt.Sprintf("%s:9090", box.BindIP())
	listener, err := tls.Listen("tcp", address, tc)
	if err != nil {
		return err
	}

	log.Printf("starting CA.gRPC at %s", address)
	var opts []grpc.ServerOption

	defaultInterceptor := interceptors.Default(
		interceptors.NewProxyBasic(),
	)

	logger, _ := zap.NewProduction()
	chainUnaryInterceptor := grpc_middleware.ChainUnaryServer(
		defaultInterceptor.InterceptUnary,
		grpc_opentracing.UnaryServerInterceptor(),
		grpc_zap.UnaryServerInterceptor(logger),
	)

	opts = append(opts, grpc.UnaryInterceptor(chainUnaryInterceptor))
	gs := grpc.NewServer(opts...)
	pb.RegisterCSRServer(gs, &csrServerHandler{
		credentials: pc,
		PrivateKey:  box.privateKey,
		Certificate: box.cert,
	})

	rs := new(server.Service)
	rs.Address = address
	rs.Server = gs
	rs.Secure = true
	box.services["ca"] = rs

	go gs.Serve(listener)
	return nil
}

type GRPCCallOption int

const (
	CallOptToken GRPCCallOption = iota + 1
	CallOptProxyCredentials
)

func GRPCCallOptionsFromContext(ctx context.Context, ot ...GRPCCallOption) ([]grpc.CallOption, error) {
	var gRPCCallOptions []grpc.CallOption

	for _, t := range ot {
		if t == CallOptToken {
			token := authpb.TokenFromContext(ctx)
			strToken, err := authpb.String(token)
			if err != nil {
				return nil, err
			}

			if token != nil {
				gRPCCallOptions = append(gRPCCallOptions, grpc.PerRPCCredentials(ga.NewGRPCClientJwt(strToken)))
			}

		} else if t == CallOptProxyCredentials {
			cred := ga.ProxyCredentialsFromContext(ctx)
			if cred != nil {
				gRPCCallOptions = append(gRPCCallOptions, grpc.PerRPCCredentials(ga.NewGRPCProxy(
					cred.Key, cred.Secret)))
			}
		}
	}
	return gRPCCallOptions, nil
}
