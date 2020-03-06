package service

import (
	pb "github.com/zoenion/service/proto"
	"github.com/zoenion/service/server"
	"log"
	"net/http"
	"strings"
)

func (box *Box) StartGateway(params *server.GatewayParams) error {
	box.serverMutex.Lock()
	defer box.serverMutex.Unlock()

	listener, err := box.listen(params.Port, params.Node.Security, params.Tls)
	if err != nil {
		return err
	}

	address := listener.Addr().String()
	if box.params.Domain != "" {
		address = strings.Replace(address, strings.Split(address, ":")[0], box.params.Domain, 1)
	}
	router := params.ProvideRouter()

	var handler http.Handler

	if len(params.MiddlewareList) > 0 {
		handler = router
		for _, m := range params.MiddlewareList {
			handler = m.Middleware(handler)
		}

	} else {
		handler = router
	}

	log.Printf("starting %s.HTTP at %s", params.Node.Name, address)
	srv := &http.Server{
		Addr:    address,
		Handler: handler,
	}
	gt := &server.Gateway{}
	gt.Server = srv
	gt.Address = address
	if params.Tls != nil {
		gt.Scheme = "https"
	} else {
		gt.Scheme = "http"
	}

	box.gateways[params.Node.Name] = gt
	go srv.Serve(listener)

	if !box.params.Autonomous && box.registry != nil {
		info := &pb.Info{}
		info.Namespace = box.params.Namespace
		info.Name = box.Name()

		n := params.Node
		n.Address = address
		info.Nodes = []*pb.Node{n}

		gt.RegistryID, err = box.registry.RegisterService(info, pb.ActionOnRegisterExistingService_AddNodes|pb.ActionOnRegisterExistingService_UpdateExisting)
		if err != nil {
			log.Println("could not register gateway")
		}
	}
	return nil
}

func (box *Box) stopGateways() error {
	box.serverMutex.Lock()
	defer box.serverMutex.Unlock()
	for name, srv := range box.gateways {
		err := srv.Stop()
		if err != nil {
			log.Printf("name: %s\t state:stopped\t error:%s\n", name, err)
		}
	}
	return nil
}
