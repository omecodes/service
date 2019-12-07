package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	crypto2 "github.com/zoenion/common/crypto"
	"github.com/zoenion/service/interceptors"
	pb "github.com/zoenion/service/proto"
	"github.com/zoenion/service/server"
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

func (box *Box) StartGatewayGRPCMapping(name string, forNode string, params *server.GatewayServiceMappingParams) error {
	if box.registry == nil && !box.params.Autonomous {
		box.serverMutex.Lock()
		defer box.serverMutex.Unlock()

		info, err := box.registry.GetService(box.params.Namespace + ":" + name)
		if err != nil {
			return err
		}

		listener, err := box.listen(true, params.Port, params.Node.Security, params.Tls)
		if err != nil {
			return err
		}

		for _, node := range info.Nodes {
			if node.Name != forNode {
				continue
			}

			address := listener.Addr().String()
			grpcServerEndpoint := flag.String("grpc-server-endpoint", node.Address, "gRPC server endpoint")
			ctx := context.Background()
			mux := runtime.NewServeMux()
			opts := []grpc.DialOption{grpc.WithInsecure()}

			err = params.Binder(ctx, mux, *grpcServerEndpoint, opts)
			if err != nil {
				return err
			}

			log.Printf("starting %s.HTTP at %s", name, address)
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

			box.gateways[name] = gt
			go srv.Serve(listener)

			if params.Node != nil && box.registry != nil {
				info := &pb.Info{}
				info.Namespace = box.params.Namespace
				info.Name = box.Name()
				info.Type = params.ServiceType

				n := new(pb.Node)
				n.Name = params.Name
				n.Address = address
				n.Protocol = pb.Protocol_Grpc
				n.Security = pb.Security_MutualTLS
				n.Ttl = 0
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

	listener, err := box.listen(false, params.Port, pb.Security_MutualTLS, params.Tls)
	if err != nil {
		return err
	}
	address := listener.Addr().String()

	log.Printf("starting %s.gRPC at %s", params.Node.Name, address)
	var opts []grpc.ServerOption
	if params.Interceptor != nil {
		opts = append(opts, grpc.StreamInterceptor(params.Interceptor.InterceptStream), grpc.UnaryInterceptor(params.Interceptor.InterceptUnary))
	}

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
			if !box.params.Autonomous {
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

func (box *Box) startCA(credentialsProvider func(...string) string) error {
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
	interceptor := interceptors.NewChainedInterceptor(map[string]*interceptors.InterceptRule{
		"SignCertificate": {
			Secure: true,
			Links:  []string{interceptors.BasicValidator},
		},
	}, interceptors.NewBasic("box-ca", credentialsProvider))
	opts = append(opts, grpc.StreamInterceptor(interceptor.InterceptStream), grpc.UnaryInterceptor(interceptor.InterceptUnary))
	gs := grpc.NewServer(opts...)
	pb.RegisterCSRServer(gs, &csrServerHandler{
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
