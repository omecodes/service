package service

import (
	"context"
	"crypto/tls"
	"flag"
	"github.com/gorilla/mux"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	http_helper "github.com/zoenion/common/xhttp"
	"github.com/zoenion/service/interceptors"
	"github.com/zoenion/service/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"log"
	"net"
	"net/http"
	"strings"
)

type Web struct {
	ResourcePathPrefix string
	ResourcesDir       string
	Tls                *tls.Config
	ClientGRPCTls      *tls.Config
	BindGRPC           WireEndpointFunc
	MiddlewareList     []http_helper.HttpMiddleware
}

type Grpc struct {
	Tls                 *tls.Config
	Interceptor         interceptors.GRPC
	RegisterHandlerFunc func(*grpc.Server)
}

type WireEndpointFunc func(ctx context.Context, serveMux *runtime.ServeMux, endpoint string, opts []grpc.DialOption) error

type gateway struct {
	name                       string
	running                    bool
	gs                         *grpc.Server
	hs                         *http.Server
	gRPC                       *Grpc
	web                        *Web
	router                     *mux.Router
	gRPCAddress, httpAddress   string
	listenerGRPC, listenerHTTP net.Listener
}

func (g *gateway) start() error {
	if g.running {
		return nil
	}

	err := g.listen()

	if err != nil {
		return err
	}

	if g.gRPC != nil {
		go g.startGRPC()
	}

	if g.web != nil {
		go g.startHTTP()
	}

	g.running = true
	return nil
}

func (g *gateway) stop() {

	g.running = false

	if g.gs != nil {
		g.gs.GracefulStop()
		_ = g.listenerGRPC.Close()
	}

	if g.hs != nil {
		ctx := context.Background()
		_ = g.hs.Shutdown(ctx)
		_ = g.listenerHTTP.Close()
	}
}

func (g *gateway) nodes() map[string]*proto.Node {
	if !g.running {
		log.Println("could not get running node, gateway is not running")
		return nil
	}
	if g.gRPC == nil && g.web == nil {
		return nil
	}

	nodes := map[string]*proto.Node{}

	if g.web != nil {
		nodes[proto.Protocol_Http.String()] = &proto.Node{
			Ttl:      -1,
			Address:  g.httpAddress,
			Protocol: proto.Protocol_Http,
		}
	}

	if g.gRPC != nil {
		nodes[proto.Protocol_Grpc.String()] = &proto.Node{
			Ttl:      -1,
			Address:  g.gRPCAddress,
			Protocol: proto.Protocol_Grpc,
		}
	}
	return nodes
}

func (g *gateway) listen() (err error) {
	if g.gRPC != nil {
		if g.gRPCAddress == "" {
			g.gRPCAddress = ":"
		}

		if g.gRPC.Tls != nil {
			g.listenerGRPC, err = tls.Listen("tcp", g.gRPCAddress, g.gRPC.Tls)
		} else {
			g.listenerGRPC, err = net.Listen("tcp", g.gRPCAddress)
		}
		if err != nil {
			return err
		}
		g.gRPCAddress = g.listenerGRPC.Addr().String()
	}

	if g.web != nil {
		if g.httpAddress == "" {
			g.httpAddress = ":"
		}

		if g.web.Tls != nil {
			g.listenerHTTP, err = tls.Listen("tcp", g.httpAddress, g.web.Tls)
		} else {
			g.listenerHTTP, err = net.Listen("tcp", g.httpAddress)
		}
		if err != nil {
			return err
		}
		g.httpAddress = g.listenerHTTP.Addr().String()
	}
	return nil
}

func (g *gateway) startGRPC() {
	log.Printf("starting %s.gRPC at %s", g.name, g.gRPCAddress)

	var opts []grpc.ServerOption
	opts = append(opts, grpc.StreamInterceptor(g.gRPC.Interceptor.InterceptStream), grpc.UnaryInterceptor(g.gRPC.Interceptor.InterceptUnary))

	g.gs = grpc.NewServer(opts...)
	g.gRPC.RegisterHandlerFunc(g.gs)
	if err := g.gs.Serve(g.listenerGRPC); err != nil {
		log.Println("gRPC server stopped, cause:", err)
	}
}

func (g *gateway) startHTTP() {
	log.Printf("starting %s.Web at %s", g.name, g.httpAddress)
	ctx := context.Background()
	endpoint := flag.String("grpc-server-endpoint", g.gRPCAddress, "gRPC server endpoint")

	router := mux.NewRouter()

	serverMux := runtime.NewServeMux()
	var opts []grpc.DialOption

	if g.web.ClientGRPCTls != nil {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(g.web.ClientGRPCTls)))
	} else {
		opts = append(opts, grpc.WithInsecure())
	}

	if err := g.web.BindGRPC(ctx, serverMux, *endpoint, opts); err != nil {
		log.Println("failed to start Web gateway, cause: ", err)
		return
	}

	var handler http.HandlerFunc

	if len(g.web.MiddlewareList) > 0 {
		m := g.web.MiddlewareList[0]
		hf := m(serverMux.ServeHTTP)
		for _, mid := range g.web.MiddlewareList[1:] {
			hf = mid(hf)
		}
		handler = http_helper.HttpBasicMiddlewareStack(context.Background(), hf, nil)
	} else {
		handler = http_helper.HttpBasicMiddlewareStack(context.Background(), serverMux.ServeHTTP, nil)
	}

	if g.web.ResourcesDir != "" {
		if g.web.ResourcePathPrefix == "" {
			g.web.ResourcePathPrefix = "/res/"
		}
		router.PathPrefix(g.web.ResourcePathPrefix).Handler(http.StripPrefix(strings.TrimRight(g.web.ResourcePathPrefix, "/"), http.FileServer(http.Dir(g.web.ResourcesDir))))
		router.PathPrefix("/api/").Handler(handler)

		g.hs = &http.Server{
			Addr:    g.httpAddress,
			Handler: router,
		}
	} else {
		g.hs = &http.Server{
			Addr:    g.httpAddress,
			Handler: handler,
		}
	}

	if err := g.hs.Serve(g.listenerHTTP); err != nil {
		log.Println("Web server stopped, cause:", err)
	}
}
