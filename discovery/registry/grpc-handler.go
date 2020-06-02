package registry

import (
	"context"
	"github.com/google/uuid"
	crypto2 "github.com/zoenion/common/crypto"
	"github.com/zoenion/common/errors"
	"github.com/zoenion/common/log"
	"github.com/zoenion/service/discovery"
	"github.com/zoenion/service/discovery/registry/dao"
	pb2 "github.com/zoenion/service/proto"
	"google.golang.org/grpc/peer"
	"io"
	"sync"
	"time"
)

type gRPCServerHandler struct {
	sync.Mutex
	stopRequested  bool
	dao            dao.ServicesDAO
	keyCounter     int
	listenersMutex sync.Mutex
	listeners      map[int]chan *pb2.Event
	// eventHandler   func(*pb2.Event)
	eventHandlers map[string]discovery.RegistryEventHandler
}

func (h *gRPCServerHandler) Register(ctx context.Context, in *pb2.RegisterRequest) (*pb2.RegisterResponse, error) {
	h.Lock()
	defer h.Unlock()

	var exists bool
	id := discovery.GenerateID(in.Service.Namespace, in.Service.Name)
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
			var oldVersion *pb2.Node

			for _, oldNode := range info.Nodes {
				if oldNode.Name == newNode.Name {
					oldVersion = oldNode
					break
				}
			}

			if oldVersion != nil {
				updated = append(updated, newNode)
			} else {
				added = append(added, newNode)
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

	if !broadcastDisabled(ctx) {
		event := &pb2.Event{
			Info: in.Service,
			Type: pb2.EventType_Register,
			Name: id,
		}

		if exists {
			event.Type = pb2.EventType_Update
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

		if !broadcastDisabled(ctx) {
			event = &pb2.Event{
				Type: pb2.EventType_DeRegister,
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
				if !broadcastDisabled(ctx) {
					event = &pb2.Event{
						Type: pb2.EventType_DeRegisterNode,
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

	apps, err := h.dao.List()
	if err != nil {
		return nil, err
	}

	out := &pb2.ListResponse{}

	for _, a := range apps {
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

	apps, err := h.dao.List()
	if err != nil {
		return nil, err
	}

	rsp := &pb2.SearchResponse{
		Services: apps,
	}
	return rsp, err
}

func (h *gRPCServerHandler) Listen(stream pb2.Registry_ListenServer) error {
	sessionClosed := false

	sessionID, err := crypto2.RandomCode(8)
	if err != nil {
		log.Error("could not generate session ID", err)
		return err
	}
	clientSource := "unknown source"

	p, ok := peer.FromContext(stream.Context())
	if ok {
		clientSource = p.Addr.String()
	}
	log.Info("[Registry] new session", log.Field("id", sessionID), log.Field("client", clientSource))

	wg := &sync.WaitGroup{}
	wg.Add(2)


	// recv routine
	go func(serverStream pb2.Registry_ListenServer, s *sync.WaitGroup) {
		defer s.Done()
		var registeredServicesNames []string
		for !h.stopRequested && !sessionClosed {
			event, err := serverStream.Recv()
			if err != nil {
				if err != io.EOF {
					log.Error("[Registry] receive event", err)
					sessionClosed = true
				}
				break
			}

			log.Info("[Registry] received event", log.Field("type", event.Type), log.Field("service", event.Name))

			switch event.Type {
			case pb2.EventType_Update, pb2.EventType_Register:

				update := event.Type == pb2.EventType_Update
				rsp, err := h.Register(stream.Context(), &pb2.RegisterRequest{
					Service: event.Info,
					Action:  event.OnRegisterExisting,
				})
				if err != nil {
					if update {
						log.Error("[Registry] update service", err)
					} else {
						log.Error("[Registry] register service", err)
					}
				} else {
					exists := false
					for _, name := range registeredServicesNames {
						if name == rsp.RegistryId {
							exists = true
							break
						}
					}
					if !exists {
						registeredServicesNames = append(registeredServicesNames, rsp.RegistryId)
					}
				}

			case pb2.EventType_DeRegister, pb2.EventType_DeRegisterNode:
				req := &pb2.DeregisterRequest{
					RegistryId: event.Name,
				}

				hasNodes := event.Info != nil && len(event.Info.Nodes) > 0
				if hasNodes {
					for _, node := range event.Info.Nodes {
						req.Nodes = append(req.Nodes, node.Name)
					}
				}

				_, err := h.Deregister(stream.Context(), req)
				if err != nil {
					if hasNodes {
						log.Error("[Registry] de-register nodes", err, log.Field("service", event.Name))
					} else {
						log.Error("[Registry] de-register service", err)
					}
				} else {
					if registeredServicesNames != nil {
						ind := -1
						for i, name := range registeredServicesNames {
							if name == event.Name {
								ind = i
								break
							}
						}

						if ind != -1 {
							if ind == 0 {
								registeredServicesNames = registeredServicesNames[1:]

							} else if ind == len(registeredServicesNames) - 1 {
								registeredServicesNames = registeredServicesNames[:ind]
							} else {
								registeredServicesNames = append(registeredServicesNames[:ind -1], registeredServicesNames[ind + 1:]...)
							}
						}
					}
				}
			}
		}
		if !h.stopRequested {
			for _, name := range registeredServicesNames {
				req := &pb2.DeregisterRequest{
					RegistryId: name,
				}
				_, err := h.Deregister(stream.Context(), req)
				if err != nil {
					log.Error("[Registry] de-register", err, log.Field("service", name))
				} else {
					log.Info("[Registry] de-register", log.Field("service", name))
				}
			}
		}
	}(stream, wg)

	// send routine
	go func(serverStream pb2.Registry_ListenServer, s *sync.WaitGroup) {
		defer s.Done()
		// let new connected client tell what he's got first - after that the server can send consistent state
		<-time.After(time.Second)

		services, err := h.dao.List()
		if err != nil {
			log.Error("[Registry] list service", err)
			return
		}

		for _, i := range services {
			ev := &pb2.Event{
				Type: pb2.EventType_Register,
				Name: discovery.GenerateID(i.Namespace, i.Name),
				Info: i,
			}
			err = stream.Send(ev)
			if err != nil {
				log.Error("[Registry] send event", err)
				sessionClosed = true
				return
			}
		}


		channel := make(chan *pb2.Event, 1)
		registrationKey := h.registerEventChannel(channel)
		defer h.deRegisterEventChannel(registrationKey)

		for !h.stopRequested && !sessionClosed {
			e, open := <-channel
			if !open {
				return
			}

			err := stream.Send(e)
			if err != nil {
				log.Error("[Registry] send event", err)
			}
		}

	}(stream, wg)

	wg.Wait()
	log.Info("[Registry] closing session", log.Field("id", sessionID), log.Field("client", clientSource))
	return nil
}

func (h *gRPCServerHandler) RegisterEventHandler(eh discovery.RegistryEventHandler) string {
	h.listenersMutex.Lock()
	defer h.listenersMutex.Unlock()
	hid := uuid.New().String()
	h.eventHandlers[hid] = eh
	return hid
}

func (h *gRPCServerHandler) DeRegisterEventHandler (id string) {
	h.listenersMutex.Lock()
	defer h.listenersMutex.Unlock()
	delete(h.eventHandlers, id)
}

func (h *gRPCServerHandler) broadcastEvent(e *pb2.Event) {
	h.listenersMutex.Lock()
	defer h.listenersMutex.Unlock()

	for _, c := range h.listeners {
		c <- e
	}

	for _, eh := range h.eventHandlers {
		go eh.Handle(e)
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
	h.stopRequested = true
	for _, l := range h.listeners {
		close(l)
	}
}

func NewGRPCServerHandler(dao dao.ServicesDAO) *gRPCServerHandler {
	return &gRPCServerHandler{
		listeners: map[int]chan *pb2.Event{},
		dao:       dao,
		eventHandlers: make(map[string] discovery.RegistryEventHandler),
	}
}
