package registry

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	pb "github.com/zoenion/service/proto"
	"google.golang.org/grpc"
	"log"
	"net"
)

func (s *Server) initGRPCHandler() {
	// starting gateways
	// gatewaySharedSecret := uuid.New().String()
	/* s.gRPCInterceptor = interceptors.NewChainedInterceptor(
		s.gRPCInterceptRules(),
		interceptors.NewGateway(gatewaySharedSecret),
	) */
	s.gRPCHandler = NewGRPCServerHandler(s.store)
}

func (s *Server) startGRPCServer() error {
	var (
		err error
	)

	addr := fmt.Sprintf("%s:9777", s.configs.BindAddress)

	if s.configs.Certificate == nil {
		s.gRPCListener, err = net.Listen("tcp", addr)

	} else {
		pool := x509.NewCertPool()
		pool.AddCert(s.configs.Certificate)

		tlsCert := tls.Certificate{
			Certificate: [][]byte{s.configs.Certificate.Raw},
			PrivateKey:  s.configs.PrivateKey,
		}

		tc := &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ServerName:   s.configs.Domain,
			ClientCAs:    pool,
		}

		s.gRPCListener, err = tls.Listen("tcp", addr, tc)
	}
	if err != nil {
		return err
	}

	srv := grpc.NewServer()
	pb.RegisterRegistryServer(srv, s.gRPCHandler)

	log.Println("starting Registry.gRPC at", addr)
	go func() {
		err = srv.Serve(s.gRPCListener)
		if err != nil {
			log.Println("could not start registry server:", err)
		}
	}()

	return nil
}
