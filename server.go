package service

import (
	"context"
	"crypto/tls"
	"github.com/gorilla/mux"
	"github.com/zoenion/service/interceptors"
	"github.com/zoenion/service/proto"
	"google.golang.org/grpc"
	"log"
	"net"
	"net/http"
)

type ServerHTTP struct {
	GetRouterFunc func(gRPCAddress string) *mux.Router
	Tls           *tls.Config
}

type ServerGRPC struct {
	Tls                 *tls.Config
	Interceptor         interceptors.GRPC
	RegisterHandlerFunc func(*grpc.Server)
}

type servers struct {
	name                       string
	running                    bool
	gs                         *grpc.Server
	hs                         *http.Server
	gRPC                       *ServerGRPC
	web                        *ServerHTTP
	gRPCAddress, httpAddress   string
	listenerGRPC, listenerHTTP net.Listener
}

func (g *servers) start() error {
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

func (g *servers) stop() {

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

func (g *servers) nodes() map[string]*proto.Node {
	if !g.running {
		log.Println("could not get running node, servers is not running")
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

func (g *servers) listen() (err error) {
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

func (g *servers) startGRPC() {
	log.Printf("starting %s.gRPC at %s", g.name, g.gRPCAddress)

	var opts []grpc.ServerOption
	opts = append(opts, grpc.StreamInterceptor(g.gRPC.Interceptor.InterceptStream), grpc.UnaryInterceptor(g.gRPC.Interceptor.InterceptUnary))

	g.gs = grpc.NewServer(opts...)
	g.gRPC.RegisterHandlerFunc(g.gs)
	if err := g.gs.Serve(g.listenerGRPC); err != nil {
		log.Println("gRPC server stopped, cause:", err)
	}
}

func (g *servers) startHTTP() {
	router := g.web.GetRouterFunc(g.gRPCAddress)
	if router == nil {
		return
	}

	log.Printf("starting %s.ServerHTTP at %s", g.name, g.httpAddress)
	g.hs = &http.Server{
		Addr:    g.httpAddress,
		Handler: router,
	}

	if err := g.hs.Serve(g.listenerHTTP); err != nil {
		log.Println("ServerHTTP server stopped, cause:", err)
	}
}
