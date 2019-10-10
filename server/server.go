package server

import (
	"crypto/tls"
	"github.com/gorilla/mux"
	"github.com/zoenion/service/gateway"
	"github.com/zoenion/service/interceptors"
	"google.golang.org/grpc"
)

type GatewayServiceMapping struct {
	ServiceName      string
	Port             int
	SecureConnection bool
	Tls              *tls.Config
	Binder           gateway.WireEndpointFunc
}

type Gateway struct {
	Port             int
	SecureConnection bool
	ProvideRouter    func() *mux.Router
	Tls              *tls.Config
}

type Service struct {
	Port                int
	SecureConnection    bool
	Tls                 *tls.Config
	Interceptor         interceptors.GRPC
	RegisterHandlerFunc func(*grpc.Server)
}
