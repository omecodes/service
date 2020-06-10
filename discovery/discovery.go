package discovery

import (
	"fmt"
	pb2 "github.com/omecodes/common/proto/service"
)

var defaultIDGenerator IDGenerator

func init() {
	defaultIDGenerator = &idGeneratorFunc{f: generateID}
}

func GenerateID(ns, name string) string {
	return defaultIDGenerator.GenerateID(ns, name)
}

func RegisterIDGenerator(g IDGenerator) {
	defaultIDGenerator = g
}

func generateID(namespace, name string) string {
	return fmt.Sprintf("%s.%s", namespace, name)
}

type IDGenerator interface {
	GenerateID(namespace, name string) string
}

type idGeneratorFunc struct {
	f func(string, string) string
}

func (ig *idGeneratorFunc) GenerateID(namespace, name string) string {
	return ig.f(namespace, name)
}

type RegistryEventHandler interface {
	Handle(*pb2.Event)
}

type eventHandlerFunc struct {
	f func(event *pb2.Event)
}

func (hf *eventHandlerFunc) Handle(event *pb2.Event) {
	hf.f(event)
}

func NewRegistryEventHandlerFunc(f func(event *pb2.Event)) RegistryEventHandler {
	return &eventHandlerFunc{
		f: f,
	}
}

type Registry interface {
	RegisterService(info *pb2.Info, action pb2.ActionOnRegisterExistingService) (string, error)
	DeregisterService(id string, nodes ...string) error
	GetService(id string) (*pb2.Info, error)
	GetNode(id string, nodeName string) (*pb2.Node, error)
	Certificate(id string) ([]byte, error)
	ConnectionInfo(id string, protocol pb2.Protocol) (*pb2.ConnectionInfo, error)
	RegisterEventHandler(h RegistryEventHandler) string
	DeregisterEventHandler(string)
	GetOfType(t pb2.Type) ([]*pb2.Info, error)
	Stop() error
}
