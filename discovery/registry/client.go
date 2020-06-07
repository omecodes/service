package registry

import (
	"context"
	"fmt"
	"github.com/omecodes/common/clone"
	"github.com/omecodes/common/errors"
	"github.com/omecodes/service/discovery"
	pb2 "github.com/omecodes/service/proto"
	"sync"
)

type client struct {
	eventHandlers map[string]discovery.RegistryEventHandler
	handler       *gRPCServerHandler
	servicesLock  sync.Mutex
	handlersLock  sync.Mutex
	syncMutex     sync.Mutex
	idGenerator   discovery.IDGenerator
	stopFunc      func() error
}

func (r *client) RegisterService(i *pb2.Info, action pb2.ActionOnRegisterExistingService) (string, error) {
	rsp, err := r.handler.Register(withBroadcastEnabled(context.Background(), false), &pb2.RegisterRequest{Service: i, Action: action})
	if err != nil {
		return "", err
	}
	return rsp.RegistryId, nil
}

func (r *client) DeregisterService(id string, nodes ...string) error {
	_, err := r.handler.Deregister(withBroadcastEnabled(context.Background(), true), &pb2.DeregisterRequest{RegistryId: id, Nodes: nodes})
	return err
}

func (r *client) GetService(id string) (*pb2.Info, error) {
	rsp, err := r.handler.Get(withBroadcastEnabled(context.Background(), true), &pb2.GetRequest{RegistryId: id})
	if err != nil {
		return nil, err
	}
	return rsp.Info, nil
}

func (r *client) GetNode(id string, nodeName string) (*pb2.Node, error) {
	info, err := r.GetService(id)
	if err != nil {
		return nil, err
	}

	for _, node := range info.Nodes {
		if node.Name == nodeName {
			return node, nil
		}
	}
	return nil, errors.NotFound
}

func (r *client) Certificate(id string) ([]byte, error) {
	r.servicesLock.Lock()
	defer r.servicesLock.Unlock()

	for _, s := range r.services() {
		if id == fmt.Sprintf("%s.%s", s.Namespace, s.Name) {
			strCert, found := s.Meta["certificate"]
			if !found {
				return nil, errors.NotFound
			}
			return []byte(strCert), nil
		}
	}
	return nil, errors.NotFound
}

func (r *client) ConnectionInfo(id string, protocol pb2.Protocol) (*pb2.ConnectionInfo, error) {
	r.servicesLock.Lock()
	defer r.servicesLock.Unlock()

	ci := new(pb2.ConnectionInfo)

	for _, s := range r.services() {
		if id == r.idGenerator.GenerateID(s.Namespace, s.Name) {
			for _, n := range s.Nodes {
				if protocol == n.Protocol {
					ci.Address = n.Address
					strCert, found := s.Meta["certificate"]
					if !found {
						return ci, nil
					}
					ci.Certificate = []byte(strCert)
					return ci, nil
				}
			}
		}
	}
	return nil, errors.NotFound
}

func (r *client) RegisterEventHandler(h discovery.RegistryEventHandler) string {
	return r.handler.RegisterEventHandler(h)
}

func (r *client) DeregisterEventHandler(hid string) {
	r.handlersLock.Lock()
	defer r.handlersLock.Unlock()
	r.handler.DeRegisterEventHandler(hid)
}

func (r *client) GetOfType(t pb2.Type) ([]*pb2.Info, error) {
	r.servicesLock.Lock()
	defer r.servicesLock.Unlock()

	var result []*pb2.Info
	for _, s := range r.services() {
		if s.Type == t {
			c := clone.New(s)
			result = append(result, c.(*pb2.Info))
		}
	}
	return result, nil
}

func (r *client) Stop() error {
	if r.stopFunc != nil {
		return r.stopFunc()
	}
	return nil
}

func (r *client) services() []*pb2.Info {
	rsp, _ := r.handler.List(context.Background(), &pb2.ListRequest{})
	return rsp.Applications
}

func (r *client) publishEvent(e pb2.Event) {
	r.handlersLock.Lock()
	r.handlersLock.Unlock()
	r.handler.broadcastEvent(&e)
}

func (r *client) ofNamespace(namespace string) []*pb2.Info {
	r.servicesLock.Lock()
	defer r.servicesLock.Unlock()
	var services []*pb2.Info
	for _, s := range r.services() {
		if namespace == "" || s.Namespace == namespace {
			services = append(services, clone.New(s).(*pb2.Info))
		}
	}
	return services
}
