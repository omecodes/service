package registry

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"github.com/omecodes/common/errors"
	"github.com/omecodes/common/jcon"
	"github.com/omecodes/service/discovery"
	"github.com/omecodes/service/discovery/registry/dao"
	"net"
)

type Server struct {
	name string
	dir  string

	stopRequested bool
	// gRPCInterceptor interceptors.GRPC
	gRPCHandler *gRPCServerHandler
	store       dao.ServicesDAO

	gRPCListener net.Listener
	apiListener  net.Listener

	configs        *Configs
	gRPCTlsConfigs tls.Config
	gRPCPort       int
}

type Configs struct {
	Name        string
	BindAddress string
	Certificate *x509.Certificate
	PrivateKey  crypto.PrivateKey
	Domain      string
	//TLS         *tls.Config
	DB jcon.Map
}

func NewServer(configs *Configs) (*Server, error) {
	s := new(Server)
	s.configs = configs

	err := s.initDB()
	if err != nil {
		return nil, err
	}

	s.initGRPCHandler()
	return s, nil
}

func (s *Server) Start() error {
	err := s.startGRPCServer()
	if err != nil {
		return errors.Errorf("could not start gRPC server")
	}

	err = s.startAPIServer()
	if err != nil {
		return errors.Errorf("could not start API server")
	}

	return nil
}

func (s *Server) onStop() {
	_ = s.apiListener.Close()
	_ = s.gRPCListener.Close()
}

func (s *Server) Client() discovery.Registry {
	return &client{handler: s.gRPCHandler, stopFunc: func() error {
		s.stopRequested = true
		_ = s.store.Stop()
		if s.gRPCListener != nil {
			_ = s.gRPCListener.Close()
		}

		if s.apiListener != nil {
			_ = s.apiListener.Close()
		}
		return nil
	}}
}
