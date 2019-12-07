package server

import (
	"context"
	"fmt"
	"github.com/zoenion/common/errors"
	"github.com/zoenion/service/discovery"
	"github.com/zoenion/service/discovery/default/server/dao"
	pb2 "github.com/zoenion/service/proto"
	"log"
	"sync"
)

type gRPCServerHandler struct {
	sync.Mutex
	dao            dao.ServicesDAO
	keyCounter     int
	listenersMutex sync.Mutex
	listeners      map[int]chan *pb2.Event
	eventHandler   func(*pb2.Event)
	idGenerator    discovery.IDGenerator
}

func (h *gRPCServerHandler) Register(ctx context.Context, in *pb2.RegisterRequest) (*pb2.RegisterResponse, error) {
	h.Lock()
	defer h.Unlock()

	var exists bool
	id := h.idGenerator.GenerateID(in.Service)
	info, err := h.dao.Find(id)
	if err != nil {
		if err != errors.NotFound {
			return nil, err
		}
	}

	exists = info != nil
	if info != nil && in.Action != pb2.ActionOnRegisterExistingService_Replace {
		// merge nodes
		var added []*pb2.Node
		var deleted []*pb2.Node
		var updated []*pb2.Node

		for _, newNode := range in.Service.Nodes {
			for _, oldNode := range info.Nodes {
				if oldNode.Name == newNode.Name {
					updated = append(updated, newNode)
				} else {
					added = append(added, newNode)
				}
			}
		}
		for _, oldNode := range info.Nodes {
			nodeDeleted := true
			for _, newNode := range in.Service.Nodes {
				if oldNode.Name == newNode.Name {
					nodeDeleted = false
					break
				}
			}

			if nodeDeleted {
				deleted = append(deleted, oldNode)
			}
		}

		var nodes []*pb2.Node
		if int(pb2.ActionOnRegisterExistingService_AddNodes) == int(in.Action)&int(pb2.ActionOnRegisterExistingService_AddNodes) {
			nodes = append(nodes, added...)
		}
		if int(pb2.ActionOnRegisterExistingService_UpdateExisting) == int(in.Action)&int(pb2.ActionOnRegisterExistingService_UpdateExisting) {
			nodes = append(nodes, updated...)
		}
		if int(pb2.ActionOnRegisterExistingService_RemoveOld) != int(in.Action)&int(pb2.ActionOnRegisterExistingService_RemoveOld) {
			nodes = append(nodes, deleted...)
		}

		in.Service.Nodes = nodes
	}

	err = h.dao.Save(in.Service)
	if err != nil {
		return nil, err
	}

	if broadcastEnabled(ctx) {
		event := &pb2.Event{
			Info: in.Service,
			Type: pb2.EventType_Registered,
			Name: id,
		}

		if exists {
			event.Type = pb2.EventType_Updated
		}
		h.broadcastEvent(event)
	}
	return &pb2.RegisterResponse{RegistryId: id}, nil
}

func (h *gRPCServerHandler) Deregister(ctx context.Context, in *pb2.DeregisterRequest) (*pb2.DeregisterResponse, error) {
	h.Lock()
	defer h.Unlock()

	var (
		err   error
		event *pb2.Event
	)

	if len(in.Nodes) == 0 {
		err = h.dao.Delete(in.RegistryId)
		if err != nil {
			return nil, err
		}

		if broadcastEnabled(ctx) {
			event = &pb2.Event{
				Type: pb2.EventType_DeRegistered,
				Name: in.RegistryId,
			}
			h.broadcastEvent(event)
		}

	} else {
		var info *pb2.Info
		info, err = h.dao.Find(in.RegistryId)
		if err != nil {
			return nil, err
		}

		var newNodes []*pb2.Node
		for _, node := range info.Nodes {
			deleted := false
			for _, nodeID := range in.Nodes {
				if node.Name == nodeID {
					deleted = true
					break
				}
			}

			if !deleted {
				newNodes = append(newNodes, node)
			} else {
				if broadcastEnabled(ctx) {
					event = &pb2.Event{
						Type: pb2.EventType_DeRegisteredNode,
						Name: in.RegistryId,
						Info: &pb2.Info{
							Nodes: []*pb2.Node{node},
						},
					}
					h.broadcastEvent(event)
				}
			}
		}

		info.Nodes = newNodes
		err = h.dao.Save(info)
	}

	return &pb2.DeregisterResponse{}, err
}

func (h *gRPCServerHandler) List(ctx context.Context, in *pb2.ListRequest) (*pb2.ListResponse, error) {
	h.Lock()
	defer h.Unlock()

	cursor, err := h.dao.List()
	if err != nil {
		return nil, err
	}

	out := &pb2.ListResponse{}

	for cursor.HasNext() {
		o, err := cursor.Next()
		if err != nil {
			return out, err
		}
		a := o.(*pb2.Info)

		if in.Namespace != "" && a.Namespace != a.Namespace {
			continue
		}
		out.Applications = append(out.Applications, a)
	}
	return out, nil
}

func (h *gRPCServerHandler) Get(ctx context.Context, in *pb2.GetRequest) (*pb2.GetResponse, error) {
	h.Lock()
	defer h.Unlock()

	info, err := h.dao.Find(in.RegistryId)
	return &pb2.GetResponse{Info: info}, err
}

func (h *gRPCServerHandler) Search(ctx context.Context, in *pb2.SearchRequest) (*pb2.SearchResponse, error) {
	h.Lock()
	defer h.Unlock()

	if in.Namespace == "" {
		return nil, errors.BadInput
	}

	c, err := h.dao.List()
	if err != nil {
		return nil, err
	}
	defer c.Close()

	rsp := &pb2.SearchResponse{}
	for err == nil && c.HasNext() {
		var o interface{}
		o, err = c.Next()
		if err == nil {
			s := o.(*pb2.Info)
			if in.Type == 0 && s.Namespace == in.Namespace || in.Type != 0 && in.Type == s.Type && s.Namespace == in.Namespace {
				rsp.Services = append(rsp.Services, s)
			}
		}
	}
	return rsp, err
}

func (h *gRPCServerHandler) Listen(in *pb2.ListenRequest, stream pb2.Registry_ListenServer) error {
	c, err := h.dao.List()
	if err != nil {
		return err
	}

	for c.HasNext() {
		o, err := c.Next()
		if err != nil {
			_ = c.Close()
			return err
		}

		i := o.(*pb2.Info)
		ev := &pb2.Event{
			Type: pb2.EventType_Registered,
			Name: h.idGenerator.GenerateID(i),
			Info: i,
		}

		err = stream.Send(ev)
		if err != nil {
			_ = c.Close()
			return err
		}
	}
	_ = c.Close()

	channel := make(chan *pb2.Event, 1)
	registrationKey := h.registerEventChannel(channel)
	defer h.deRegisterEventChannel(registrationKey)
	//defer close(channel)

	for {
		e, _ := <-channel
		if e == nil {
			log.Println("closed channel")
			return errors.New("event channel closed")
		}

		log.Println(e.Type, e.Name)
		err := stream.Send(e)
		if err != nil {
			return fmt.Errorf("could not send event: %s", err)
		}
	}
}

func (h *gRPCServerHandler) RegisterEventHandler(eh func(event *pb2.Event)) {
	h.eventHandler = eh
}

func (h *gRPCServerHandler) broadcastEvent(e *pb2.Event) {
	h.listenersMutex.Lock()
	defer h.listenersMutex.Unlock()

	for _, c := range h.listeners {
		c <- e
	}

	if h.eventHandler != nil {
		go h.eventHandler(e)
	}
}

func (h *gRPCServerHandler) registerEventChannel(channel chan *pb2.Event) int {
	h.listenersMutex.Lock()
	defer h.listenersMutex.Unlock()
	h.keyCounter++
	h.listeners[h.keyCounter] = channel
	return h.keyCounter
}

func (h *gRPCServerHandler) deRegisterEventChannel(key int) {
	h.listenersMutex.Lock()
	defer h.listenersMutex.Unlock()

	c := h.listeners[key]
	defer close(c)

	delete(h.listeners, key)
}

func (h *gRPCServerHandler) Stop() {
	h.listenersMutex.Lock()
	defer h.listenersMutex.Unlock()
	for _, l := range h.listeners {
		close(l)
	}
}

func NewGRPCServerHandler(dao dao.ServicesDAO) *gRPCServerHandler {
	return &gRPCServerHandler{
		listeners:   map[int]chan *pb2.Event{},
		dao:         dao,
		idGenerator: idGenerator(0),
	}
}
