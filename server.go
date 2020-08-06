package service

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	grpc_gateway "github.com/omecodes/common/grpc-gateway"
	pb "github.com/omecodes/common/proto/service"
	"github.com/omecodes/service/interceptors"
	"google.golang.org/grpc"
	"net/http"
)

type WireEndpointFunc func(ctx context.Context, serveMux *runtime.ServeMux, endpoint string, opts []grpc.DialOption) error

type GatewayGrpcMappingParams struct {
	ForceRegister  bool
	ServiceName    string
	TargetNodeName string
	NodeName       string
	Port           int
	Tls            *tls.Config
	ServiceType    pb.Type
	Security       pb.Security
	Binder         WireEndpointFunc
	MuxWrapper     grpc_gateway.MuxWrapper
	Meta           map[string]string
}

type GatewayNodeParams struct {
	ForceRegister  bool
	MiddlewareList []mux.MiddlewareFunc
	Port           int
	ProvideRouter  func() *mux.Router
	Tls            *tls.Config
	ServiceType    pb.Type
	Node           *pb.Node
}

type GrpcNodeParams struct {
	ForceRegister       bool
	Port                int
	Tls                 *tls.Config
	Interceptor         interceptors.GRPC
	RegisterHandlerFunc func(*grpc.Server)
	ServiceType         pb.Type
	Meta                map[string]string
	Node                *pb.Node
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
	return g.Server.Shutdown(nil)
}