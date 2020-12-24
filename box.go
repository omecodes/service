package service

import (
	"sync"

	"github.com/omecodes/libome"
)

type Box struct {
	serverMutex   sync.Mutex
	dialerMutex   sync.Mutex
	servicesMutex sync.Mutex

	*Options

	gRPCNodes map[string]*gPRCNode
	httpNodes map[string]*httpNode

	services    map[uint32]*ome.ServiceInfo
	dialerCache map[string]Dialer
}

func CreateBox(opts ...Option) *Box {
	b := &Box{Options: new(Options)}
	for _, o := range opts {
		o(b.Options)
	}

	b.services = map[uint32]*ome.ServiceInfo{}
	b.dialerCache = map[string]Dialer{}
	b.httpNodes = map[string]*httpNode{}
	b.gRPCNodes = map[string]*gPRCNode{}
	return b
}

func (box *Box) Service(serviceType uint32) *ome.ServiceInfo {
	box.servicesMutex.Lock()
	defer box.servicesMutex.Unlock()

	return box.services[serviceType]
}

func (box *Box) ServiceNode(serviceType uint32, name string) *ome.Node {
	box.servicesMutex.Lock()
	defer box.servicesMutex.Unlock()

	serv, found := box.services[serviceType]
	if !found {
		return nil
	}

	for _, node := range serv.Nodes {
		if node.Id == name {
			return node
		}
	}
	return nil
}

func (box *Box) SaveService(serviceType uint32, info *ome.ServiceInfo) {
	box.servicesMutex.Lock()
	defer box.servicesMutex.Unlock()
	box.services[serviceType] = info
}

func (box *Box) AllServices() []*ome.ServiceInfo {
	box.servicesMutex.Lock()
	defer box.servicesMutex.Unlock()

	var infoList []*ome.ServiceInfo
	for _, info := range box.services {
		infoList = append(infoList, info)
	}

	return infoList
}

func (box *Box) SaveNode(serviceType uint32, serviceID string, node *ome.Node) *ome.ServiceInfo {
	info := box.Service(serviceType)
	if info == nil {
		box.SaveService(serviceType, info)
		info = new(ome.ServiceInfo)
		info.Id = serviceID
		info.Type = serviceType
		if info.Meta == nil {
			info.Meta = map[string]string{}
		}
	}
	info.Nodes = append(info.Nodes, node)
	return info
}

func (box *Box) DeleteNode(serviceType uint32, serviceID string, nodeID string) (*ome.ServiceInfo, bool) {
	deleted := false
	info := box.Service(serviceType)
	if info != nil {
		var newNodeList []*ome.Node
		for _, node := range info.Nodes {
			different := node.Id != nodeID
			deleted = deleted || different
			if different {
				newNodeList = append(newNodeList, node)
			}
		}
		info.Nodes = newNodeList
	}
	return info, deleted
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
