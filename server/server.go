package server

import (
	"crypto/tls"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/zoenion/service/gateway"
	"github.com/zoenion/service/interceptors"
	pb "github.com/zoenion/service/proto"
	"google.golang.org/grpc"
	"net/http"
)

type GatewayServiceMappingParams struct {
	ServiceName      string
	Port             int
	SecureConnection bool
	Tls              *tls.Config
	Binder           gateway.WireEndpointFunc
}

type GatewayParams struct {
	Port             int
	SecureConnection bool
	ProvideRouter    func() *mux.Router
	Tls              *tls.Config
}

type ServiceParams struct {
	Port                int
	Tls                 *tls.Config
	Interceptor         interceptors.GRPC
	RegisterHandlerFunc func(*grpc.Server)
	Info                *pb.Info
}

type Service struct {
	Secure     bool
	Address    string
	RegistryID string
	Server     *grpc.Server
}

func (s *Service) Stop() {
	s.Server.Stop()
}

type Gateway struct {
	Scheme  string
	Address string
	Server  *http.Server
}

func (g *Gateway) URL() string {
	return fmt.Sprintf("%s://%s", g.Scheme, g.Address)
}

func (g *Gateway) Stop() error {
	return g.Server.Shutdown(nil)
}
