package server

import (
	"crypto/tls"
	"github.com/google/uuid"
	"github.com/zoenion/service/interceptors"
	pb "github.com/zoenion/service/proto"
	"google.golang.org/grpc"
	"log"
	"net"
)

func (s *Server) gRPCInterceptRules() interceptors.MethodRules {
	rule := &interceptors.InterceptRule{Secure: true, Links: []string{interceptors.GatewayValidator}}
	return interceptors.MethodRules{
		"Register":   rule,
		"Deregister": rule,
		"List":       rule,
		"Get":        rule,
		"Search":     rule,
		"Listen":     rule,
	}
}

func (s *Server) initGRPCHandler() {
	// starting gateways
	gatewaySharedSecret := uuid.New().String()
	s.gRPCInterceptor = interceptors.NewChainedInterceptor(
		s.gRPCInterceptRules(),
		interceptors.NewGateway(gatewaySharedSecret),
	)
	s.gRPCHandler = NewGRPCServerHandler(s.store)
}

func (s *Server) startGRPCServer() error {
	var (
		err error
	)

	if s.configs.TLS == nil {
		s.gRPCListener, err = net.Listen("tcp", s.configs.BindAddress)
	} else {
		s.gRPCListener, err = tls.Listen("tcp", s.configs.BindAddress, s.configs.TLS)
	}
	if err != nil {
		return err
	}

	srv := grpc.NewServer()
	pb.RegisterRegistryServer(srv, s.gRPCHandler)

	log.Println("starting Registry.gRPC at", s.gRPCListener.Addr())
	go srv.Serve(s.gRPCListener)

	return nil
}
