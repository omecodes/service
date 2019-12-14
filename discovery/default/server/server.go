package server

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"github.com/zoenion/common/conf"
	"github.com/zoenion/common/errors"
	"github.com/zoenion/service/discovery"
	"github.com/zoenion/service/discovery/default/server/dao"
	"github.com/zoenion/service/interceptors"
	"log"
	"net"
)

type Server struct {
	name            string
	dir             string
	gRPCInterceptor interceptors.GRPC
	gRPCHandler     *gRPCServerHandler
	store           dao.ServicesDAO

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
	DB conf.Map
}

func New(configs *Configs) (*Server, error) {
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
		log.Println(err)
		return errors.Errorf("could not start gRPC server")
	}

	err = s.startAPIServer()
	if err != nil {
		log.Println(err)
		return errors.Errorf("could not start API server")
	}

	return nil
}

func (s *Server) onStop() {
	_ = s.apiListener.Close()
	_ = s.gRPCListener.Close()
}

func (s *Server) Client() discovery.Registry {
	return &client{handler: s.gRPCHandler}
}
