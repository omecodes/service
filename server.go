package service

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/omecodes/libome"
	"google.golang.org/grpc"
)

type WireEndpointFunc func(ctx context.Context, serveMux *runtime.ServeMux, endpoint string, opts []grpc.DialOption) error

type ACMEServiceGatewayParams struct {
	ForceRegister  bool
	ServiceName    string
	TargetNodeName string
	NodeName       string
	ServiceType    ome.ServiceType
	Binder         WireEndpointFunc
	MuxWrapper     MuxWrapper
	Meta           map[string]string
}

type GatewayGrpcMappingParams struct {
	ForceRegister  bool
	ServiceName    string
	TargetNodeName string
	NodeName       string
	Port           int
	Tls            *tls.Config
	ServiceType    ome.ServiceType
	Security       ome.Security
	Binder         WireEndpointFunc
	MuxWrapper     MuxWrapper
	Meta           map[string]string
}

type GatewayParams struct {
	ForceRegister  bool
	MiddlewareList []mux.MiddlewareFunc
	Port           int
	ProvideRouter  func() *mux.Router
	Tls            *tls.Config
	ServiceType    ome.ServiceType
	Node           *ome.Node
}

type AcmeGatewayParams struct {
	ForceRegister  bool
	MiddlewareList []mux.MiddlewareFunc
	ProvideRouter  func() *mux.Router
	ServiceType    ome.ServiceType
	Node           *ome.Node
}

type GrpcNodeParams struct {
	ForceRegister       bool
	Port                int
	Tls                 *tls.Config
	Interceptor         MergedInterceptor
	RegisterHandlerFunc func(*grpc.Server)
	ServiceType         ome.ServiceType
	Meta                map[string]string
	Node                *ome.Node
}

type gPRCNode struct {
	Name    string
	Secure  bool
	Address string
	Server  *grpc.Server
}

func (s *gPRCNode) Stop() {
	s.Server.Stop()
}

type httpNode struct {
	Name    string
	Scheme  string
	Address string
	Server  *http.Server
}

func (g *httpNode) URL() string {
	return fmt.Sprintf("%s://%s", g.Scheme, g.Address)
}

func (g *httpNode) Stop() error {
	return g.Server.Shutdown(context.Background())
}
