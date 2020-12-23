package service

import (
	"sync"

	"github.com/omecodes/libome"
)

type Box struct {
	serverMutex sync.Mutex
	dialerMutex sync.Mutex

	*options

	gRPCNodes map[string]*gPRCNode
	httpNodes map[string]*httpNode

	info        *ome.ServiceInfo
	dialerCache map[string]Dialer
}

func CreateBox(opts ...Option) *Box {
	b := &Box{options: new(options)}
	for _, o := range opts {
		o(b.options)
	}

	b.dialerCache = map[string]Dialer{}
	b.httpNodes = map[string]*httpNode{}
	b.gRPCNodes = map[string]*gPRCNode{}
	return b
}

func (box *Box) Update(opts ...Option) {
	if box.options == nil {
		box.options = new(options)
	}
	for _, o := range opts {
		o(box.options)
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
