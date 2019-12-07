package service

import (
	pb "github.com/zoenion/service/proto"
	"github.com/zoenion/service/server"
	"log"
	"net/http"
	"strings"
)

func (box *Box) StartGateway(name string, params *server.GatewayParams) error {
	box.serverMutex.Lock()
	defer box.serverMutex.Unlock()

	listener, err := box.listen(true, params.Port, pb.Security_None, params.Tls)
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
		for _, m := range params.MiddlewareList {
			handler = m.Middleware(router)
		}
	} else {
		handler = router
	}

	log.Printf("starting %s.HTTP at %s", name, address)
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

	box.gateways[name] = gt
	go srv.Serve(listener)

	if !box.params.Autonomous && params.Node != nil && box.registry != nil {
		info := &pb.Info{}
		info.Namespace = box.params.Namespace
		info.Name = box.Name()

		n := new(pb.Node)
		n.Name = params.Name
		n.Address = address
		n.Protocol = pb.Protocol_Grpc
		n.Security = pb.Security_MutualTLS
		n.Ttl = 0
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
		log.Printf("name: %s\t state:stopped\t error:%s\n", name, err)
	}
	return nil
}
