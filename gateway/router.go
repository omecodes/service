package gateway

import (
	"context"
	"crypto/tls"
	"flag"
	"github.com/gorilla/mux"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/zoenion/common/xhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"log"
	"net/http"
)

type WireEndpointFunc func(ctx context.Context, serveMux *runtime.ServeMux, endpoint string, opts []grpc.DialOption) error

// SubRouter
type SubRouter interface {
	Prefix() string
	Router() *mux.Router
}

// NewSubRouter
func NewSubRouter(prefix string, router *mux.Router) SubRouter {
	return &subRouter{
		router: router,
		prefix: prefix,
	}
}

type subRouter struct {
	router *mux.Router
	prefix string
}

func (s *subRouter) Prefix() string {
	return s.prefix
}

func (s *subRouter) Router() *mux.Router {
	return s.router
}

// NewGroupedRouters
func NewGroupedRouters(subRouters ...SubRouter) Gateway {
	return &groupedRouters{
		subRouters: subRouters,
	}
}

type groupedRouters struct {
	subRouters []SubRouter
}

func (g *groupedRouters) Router() (*mux.Router, error) {
	router := mux.NewRouter()
	for _, sub := range g.subRouters {
		prefix := sub.Prefix()
		router.PathPrefix(prefix).Handler(http.StripPrefix(prefix, sub.Router()))
	}
	return router, nil
}

// NewGRPCBinding
func NewGRPCBinding(gRPCAddress string, binderFunc WireEndpointFunc, clientTLS *tls.Config, middlewareList ...xhttp.HttpMiddleware) Gateway {
	return &gRPCBinding{
		gRPCAddress:    gRPCAddress,
		binderFunc:     binderFunc,
		clientTLS:      clientTLS,
		middlewareList: middlewareList,
	}
}

type gRPCBinding struct {
	gRPCAddress    string
	clientTLS      *tls.Config
	binderFunc     WireEndpointFunc
	middlewareList []xhttp.HttpMiddleware
}

func (g *gRPCBinding) Router() (*mux.Router, error) {
	ctx := context.Background()
	endpoint := flag.String("grpc-server-endpoint", g.gRPCAddress, "gRPC server endpoint")
	serverMux := runtime.NewServeMux()
	var opts []grpc.DialOption

	if g.clientTLS != nil {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(g.clientTLS)))
	} else {
		opts = append(opts, grpc.WithInsecure())
	}

	if err := g.binderFunc(ctx, serverMux, *endpoint, opts); err != nil {
		log.Println("failed to start HTTP gateway, cause: ", err)
		return nil, err
	}

	var handler http.Handler

	if len(g.middlewareList) > 0 {
		m := g.middlewareList[0]
		hf := m(serverMux.ServeHTTP)
		for _, mid := range g.middlewareList[1:] {
			hf = mid(hf)
		}
		handler = xhttp.Logger(hf)
	} else {
		handler = xhttp.Logger(serverMux)
	}

	mr := mux.NewRouter()
	mr.NewRoute().PathPrefix("/").Handler(handler)
	return mr, nil
}
