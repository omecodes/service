package service

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/omecodes/libome"
	"google.golang.org/grpc"
)

type WireEndpointFunc func(ctx context.Context, serveMux *runtime.ServeMux, endpoint string, opts []grpc.DialOption) error

type ACMENodeGatewayParams struct {
	ServiceName    string
	TargetNodeName string
	NodeName       string
	ServiceType    uint32
	Binder         WireEndpointFunc
	MuxWrapper     MuxWrapper
}

type NodeGatewayParams struct {
	ServiceName    string
	TargetNodeName string
	NodeName       string
	ServiceType    uint32
	Security       ome.Security
	Binder         WireEndpointFunc
	MuxWrapper     MuxWrapper
}

type GatewayParams struct {
	ForceRegister  bool
	MiddlewareList []mux.MiddlewareFunc
	ProvideRouter  func() *mux.Router
	ServiceType    uint32
	Node           *ome.Node
}

type AcmeGatewayParams struct {
	ForceRegister  bool
	MiddlewareList []mux.MiddlewareFunc
	ProvideRouter  func() *mux.Router
	ServiceType    uint32
	Node           *ome.Node
}

type NodeParams struct {
	ForceRegister       bool
	RegisterHandlerFunc func(*grpc.Server)
	ServiceType         uint32
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
