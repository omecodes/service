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
	gs "github.com/zoenion/common/grpc-session"
	"github.com/zoenion/common/log"
	"github.com/zoenion/service/interceptors"
	pb "github.com/zoenion/service/proto"
	"github.com/zoenion/service/server"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"net/http"
	"strings"
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
			if box.params.Domain != "" {
				address = strings.Replace(address, box.params.Ip, box.params.Domain, 1)
			}

			endpoint := fmt.Sprintf("%s-gateway-endpoint", params.TargetNodeName)
			grpcServerEndpoint := flag.String(endpoint, node.Address, "gRPC server endpoint")
			ctx := context.Background()
			mux := runtime.NewServeMux(runtime.WithForwardResponseOption(gs.SetCookieFromGRPCMetadata))
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

			log.Info("starting http server", log.Field("service", params.NodeName), log.Field("address", address))
			srv := &http.Server{Addr: address}

			if params.MuxWrapper != nil {
				srv.Handler = params.MuxWrapper(mux)
			} else {
				srv.Handler = mux
			}

			gt := &server.Gateway{}
			gt.Server = srv
			gt.Address = address
			if node.Security == pb.Security_None {
				gt.Scheme = "http"
			} else {
				gt.Scheme = "https"
			}

			box.gateways[params.NodeName] = gt
			go srv.Serve(listener)

			if params.ForceRegister || !box.params.CA && !box.params.Autonomous {
				if box.registry != nil {
					inf := &pb.Info{}
					inf.Namespace = box.params.Namespace
					inf.Name = box.Name()
					inf.Type = info.Type
					n := &pb.Node{}
					n.Name = params.NodeName
					n.Address = address
					n.Protocol = pb.Protocol_Http
					n.Security = params.Security
					n.Meta = params.Meta
					inf.Nodes = []*pb.Node{n}

					gt.RegistryID, err = box.registry.RegisterService(inf, pb.ActionOnRegisterExistingService_AddNodes|pb.ActionOnRegisterExistingService_UpdateExisting)
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

func (box *Box) StartService(params *server.ServiceParams) error {
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

	log.Info("starting gRPC server", log.Field("service", params.Node.Name), log.Field("address", address))
	var opts []grpc.ServerOption

	defaultInterceptor := interceptors.Default(
		interceptors.ProxyBasic(),
		interceptors.Basic(),
		interceptors.Jwt(box.BearerTokenVerifyFunc),
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
	opts = append(opts, grpc.StreamInterceptor(chainStreamInterceptor), grpc.UnaryInterceptor(chainUnaryInterceptor))

	srv := grpc.NewServer(opts...)
	rs := new(server.Service)
	rs.Address = address
	rs.Server = srv
	rs.Secure = params.Tls != nil

	box.services[params.Node.Name] = rs

	params.RegisterHandlerFunc(srv)
	go srv.Serve(listener)

	if params.ForceRegister || !box.params.CA && !box.params.Autonomous && params.Node != nil && box.registry != nil {
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
			log.Error("could not register service", err, log.Field("name", params.Node.Name))
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
			log.Error("could not deregister service", err, log.Field("name", name))
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
					log.Error("could not de register service", err, log.Field("name", name))
				}
			}
		}
	}
	box.services = map[string]*server.Service{}
	return nil
}

func (box *Box) StartCAService(credentialsVerifier ga.CredentialsVerifyFunc) error {
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

	address := fmt.Sprintf("%s:9090", box.Domain())

	listener, err := tls.Listen("tcp", address, tc)
	if err != nil {
		return err
	}

	log.Info("starting gRPC server", log.Field("service", "CA"), log.Field("at", address))
	var opts []grpc.ServerOption

	defaultInterceptor := interceptors.Default(
		interceptors.Basic(),
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

	rs := new(server.Service)
	rs.Address = address
	rs.Server = srv
	rs.Secure = true
	box.services["ca"] = rs

	go srv.Serve(listener)
	return nil
}
