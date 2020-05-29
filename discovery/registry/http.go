package registry

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/zoenion/common/log"
	pb "github.com/zoenion/service/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"net"
	"net/http"
)

func (s *Server) startAPIServer() error {
	var (
		err error
	)

	addr := fmt.Sprintf("%s:9780", s.configs.BindAddress)
	var opts []grpc.DialOption

	if s.configs.Certificate == nil {
		opts = []grpc.DialOption{grpc.WithInsecure()}
		s.apiListener, err = net.Listen("tcp", addr)

	} else {
		// HTTP server TLS config
		tlsCert := tls.Certificate{
			Certificate: [][]byte{s.configs.Certificate.Raw},
			PrivateKey:  s.configs.PrivateKey,
		}
		tc := &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
		}

		// HTTP to gRPC mapping client TLS config
		pool := x509.NewCertPool()
		pool.AddCert(s.configs.Certificate)
		clientTLS := &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			RootCAs:      pool,
		}

		opts = []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(clientTLS))}
		s.apiListener, err = tls.Listen("tcp", addr, tc)
	}
	if err != nil {
		return err
	}

	address := s.gRPCListener.Addr().String()
	grpcServerEndpoint := flag.String("grpc-server-endpoint", address, "gRPC server endpoint")

	ctx := context.Background()
	mux := runtime.NewServeMux()

	err = pb.RegisterRegistryHandlerFromEndpoint(ctx, mux, *grpcServerEndpoint, opts)
	if err != nil {
		return err
	}

	log.Info("starting Registry.HTTP", log.Field("at", addr))
	srv := &http.Server{
		Addr:    s.apiListener.Addr().String(),
		Handler: mux,
	}
	go srv.Serve(s.apiListener)
	return nil
}
