package proto

type RegistryEventHandler interface {
	Handle(*Event)
}

type eventHandlerFunc struct {
	f func(event *Event)
}

func (hf *eventHandlerFunc) Handle(event *Event) {
	hf.f(event)
}

func EventHandlerFunc(f func(*Event)) RegistryEventHandler {
	return &eventHandlerFunc{f: f}
}

type Registry interface {
	Register(info *Info) (string, error)
	Deregister(id string) error
	Get(id string) (*Info, error)
	Certificate(id string) ([]byte, error)
	ConnectionInfo(id string, protocol Protocol) (*ConnectionInfo, error)
	RegisterEventHandler(h RegistryEventHandler) string
	DeregisterEventHandler(string)
	GetOfType(t Type) ([]*Info, error)
}
