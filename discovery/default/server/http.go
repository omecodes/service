package server

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	pb "github.com/zoenion/service/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"log"
	"net"
	"net/http"
)

func (s *Server) startAPIServer() error {
	var (
		err error
	)

	addr := fmt.Sprintf("%s:", s.configs.BindAddress)

	if s.configs.TLS == nil {
		s.apiListener, err = net.Listen("tcp", addr)
	} else {
		s.apiListener, err = tls.Listen("tcp", addr, s.configs.TLS)
	}
	if err != nil {
		return err
	}

	address := s.gRPCListener.Addr().String()
	grpcServerEndpoint := flag.String("grpc-server-endpoint", address, "gRPC server endpoint")

	ctx := context.Background()
	mux := runtime.NewServeMux()
	opts := []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(s.configs.TLS))}

	err = pb.RegisterCSRHandlerFromEndpoint(ctx, mux, *grpcServerEndpoint, opts)
	if err != nil {
		return err
	}

	log.Printf("starting %s.HTTP at %s", s.configs.BindAddress, address)
	srv := &http.Server{
		Addr:    s.apiListener.Addr().String(),
		Handler: mux,
	}
	go srv.Serve(s.apiListener)
	return nil
}
