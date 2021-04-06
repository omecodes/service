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

type PublicNodeGatewayParams struct {
	ServiceName    string
	TargetNodeName string
	NodeName       string
	ServiceType    uint32
	ServiceID      string
	Email          string
	Binder         WireEndpointFunc
	MuxWrapper     MuxWrapper
	Meta           MD
}

type NodeGatewayParams struct {
	ServiceName    string
	TargetNodeName string
	NodeName       string
	ServiceType    uint32
	ServiceID      string
	Security       ome.Security
	Binder         WireEndpointFunc
	MuxWrapper     MuxWrapper
	Meta           MD
}

type HTTPServerParams struct {
	MiddlewareList []mux.MiddlewareFunc
	ProvideRouter  func() *mux.Router
	Security       ome.Security
	ServiceType    uint32
	ServiceID      string
	Name           string
	Meta           MD
}

type HTTPGatewayParams struct {
	Email          string
	MiddlewareList []mux.MiddlewareFunc
	ProvideRouter  func() *mux.Router
	ServiceType    uint32
	ServiceID      string
	Name           string
	Meta           MD
}

type NodeParams struct {
	RegisterHandlerFunc func(*grpc.Server)
	ServiceType         uint32
	ServiceID           string
	Name                string
	Meta                MD
}

type gPRCNode struct {
	Name      string
	Secure    bool
	ServiceID string
	Address   string
	Server    *grpc.Server
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
