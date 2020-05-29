package registry

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/zoenion/common/log"
	pb "github.com/zoenion/service/proto"
	"google.golang.org/grpc"
	"net"
)

func (s *Server) initGRPCHandler() {
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
	go func() {
		err = srv.Serve(s.gRPCListener)
		if err != nil {
			log.Error("could not start registry server:", err)
		}
	}()
	return nil
}
