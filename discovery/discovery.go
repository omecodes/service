package discovery

import "github.com/zoenion/service/proto"

type RegistryEventHandler interface {
	Handle(*proto.Event)
}

type eventHandlerFunc struct {
	f func(event *proto.Event)
}

func (hf *eventHandlerFunc) Handle(event *proto.Event) {
	hf.f(event)
}

func EventHandlerFunc(f func(*proto.Event)) RegistryEventHandler {
	return &eventHandlerFunc{f: f}
}

type Registry interface {
	Register(info *proto.Info) (string, error)
	Deregister(id string) error
	Get(id string) (*proto.Info, error)
	Certificate(id string) ([]byte, error)
	ConnectionInfo(id string, protocol proto.Protocol) (*proto.ConnectionInfo, error)
	RegisterEventHandler(h RegistryEventHandler) string
	DeregisterEventHandler(string)
	GetOfType(t proto.Type) ([]*proto.Info, error)
}
