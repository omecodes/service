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

func (box *Box) StartGatewayGRPCMapping(name string, params *server.GatewayServiceMappingParams) error {
	if box.registry == nil {
		box.serverMutex.Lock()
		defer box.serverMutex.Unlock()

		info, err := box.registry.GetService(box.params.Namespace + ":" + name)
		if err != nil {
			return err
		}

		listener, err := box.listen(true, params.SecureConnection, params.Port, params.Tls)
		if err != nil {
			return err
		}

		address := listener.Addr().String()
		grpcServerEndpoint := flag.String("grpc-server-endpoint", info.ServiceNode.Address, "gRPC server endpoint")
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
		return nil
	}
	return errors.New("not found")
}

func (box *Box) StartService(name string, params *server.ServiceParams) error {
	box.serverMutex.Lock()
	defer box.serverMutex.Unlock()

	listener, err := box.listen(false, true, params.Port, params.Tls)
	if err != nil {
		return err
	}
	address := listener.Addr().String()
	if params.Info == nil {
		params.Info = new(pb.Info)
	}

	log.Printf("starting %s.gRPC at %s", name, address)
	var opts []grpc.ServerOption
	if params.Interceptor != nil {
		opts = append(opts, grpc.StreamInterceptor(params.Interceptor.InterceptStream), grpc.UnaryInterceptor(params.Interceptor.InterceptUnary))
	}

	srv := grpc.NewServer(opts...)
	rs := new(server.Service)
	rs.Address = address
	rs.Server = srv
	rs.Secure = params.Tls != nil

	box.services[name] = rs

	params.RegisterHandlerFunc(srv)
	go srv.Serve(listener)

	if params.Info != nil && box.registry != nil {
		params.Info.Namespace = box.params.Namespace
		params.Info.Name = box.Name()
		params.Info.ServiceNode = new(pb.Node)
		params.Info.ServiceNode.Address = address
		params.Info.ServiceNode.Protocol = pb.Protocol_Grpc
		params.Info.ServiceNode.Security = pb.Security_MutualTLS
		params.Info.ServiceNode.Ttl = 0
		rs.RegistryID, err = box.registry.RegisterService(params.Info)
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
	if rs != nil && box.registry != nil {
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
			err := box.registry.DeregisterService(rs.RegistryID)
			if err != nil {
				log.Println("could not deregister service:", name)
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

	address := fmt.Sprintf("%s:9090", box.Ip())
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
