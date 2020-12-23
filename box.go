package service

import (
	"sync"

	"github.com/omecodes/libome"
)

type Box struct {
	serverMutex sync.Mutex
	dialerMutex sync.Mutex

	*Options

	gRPCNodes map[string]*gPRCNode
	httpNodes map[string]*httpNode

	info        *ome.ServiceInfo
	dialerCache map[string]Dialer
}

func CreateBox(opts ...Option) *Box {
	b := &Box{Options: new(Options)}
	for _, o := range opts {
		o(b.Options)
	}

	b.dialerCache = map[string]Dialer{}
	b.httpNodes = map[string]*httpNode{}
	b.gRPCNodes = map[string]*gPRCNode{}
	return b
}

func (box *Box) Update(opts ...Option) {
	if box.Options == nil {
		box.Options = new(Options)
	}
	for _, o := range opts {
		o(box.Options)
	}
}

// Stop stops all started services and gateways
func (box *Box) Stop() {
	_ = box.stopNodes()
	_ = box.stopGateways()
	if box.registry != nil {
		_ = box.registry.Stop()
	}
}
