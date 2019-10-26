package service

import (
	"github.com/zoenion/service/server"
	"log"
	"net/http"
	"strings"
)

func (box *Box) StartGateway(name string, params *server.GatewayParams) error {
	box.serverMutex.Lock()
	defer box.serverMutex.Unlock()

	listener, err := box.listen(true, params.SecureConnection, params.Port, params.Tls)
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
