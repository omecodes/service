package service

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	pb "github.com/zoenion/service/proto"
	"google.golang.org/grpc"
	"log"
	"net"
)

func (r *SyncedRegistry) Serve(addr string, tc *tls.Config) error {
	var (
		listener net.Listener
		err      error
	)

	if tc == nil {
		listener, err = net.Listen("tcp", addr)
	} else {
		listener, err = tls.Listen("tcp", addr, tc)
	}

	if err != nil {
		return err
	}

	srv := grpc.NewServer()
	pb.RegisterRegistryServer(srv, r)
	go log.Println("registry done serving:", srv.Serve(listener))
	log.Println("start gRPC.Registry server at:", listener.Addr())
	return nil
}

func (r *SyncedRegistry) Register(ctx context.Context, in *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	r.saveService(in.Service)
	return &pb.RegisterResponse{RegistryId: in.Service.Namespace + ":" + in.Service.Name}, nil
}

func (r *SyncedRegistry) Deregister(ctx context.Context, in *pb.DeregisterRequest) (*pb.DeregisterResponse, error) {
	err := r.DeregisterService(in.RegistryId)
	return &pb.DeregisterResponse{}, err
}

func (r *SyncedRegistry) List(ctx context.Context, in *pb.ListRequest) (*pb.ListResponse, error) {
	result := r.ofNamespace(in.Namespace)
	return &pb.ListResponse{Applications: result}, nil
}

func (r *SyncedRegistry) Get(ctx context.Context, in *pb.GetRequest) (*pb.GetResponse, error) {
	info := r.get(in.RegistryId)
	return &pb.GetResponse{Info: info}, nil
}

func (r *SyncedRegistry) Search(ctx context.Context, in *pb.SearchRequest) (*pb.SearchResponse, error) {
	list := r.ofNamespace(in.Namespace)
	var result []*pb.Info
	for _, s := range list {
		if s.Type == in.Type {
			result = append(result, s)
		}
	}
	return &pb.SearchResponse{Services: result}, nil
}

func (r *SyncedRegistry) Listen(in *pb.ListenRequest, stream pb.Registry_ListenServer) error {
	list := r.ofNamespace(in.Namespace)

	for _, i := range list {
		ev := &pb.Event{
			Type: pb.EventType_Registered,
			Name: fmt.Sprintf("%s:%s", i.Namespace, i.Name),
			Info: i,
		}

		err := stream.Send(ev)
		if err != nil {
			return err
		}
	}

	channel := make(chan *pb.Event, 1)
	registrationKey := r.registerEventChannel(channel)
	defer r.deRegisterEventChannel(registrationKey)
	defer close(channel)

	for {
		e, _ := <-channel
		if e == nil {
			log.Println("closed channel")
			return errors.New("event channel closed")
		}

		err := stream.Send(e)
		if err != nil {
			return fmt.Errorf("could not send event: %s", err)
		}
	}
}

func (r *SyncedRegistry) broadcastEvent(e *pb.Event) {
	r.listenersMutex.Lock()
	defer r.listenersMutex.Unlock()
	for _, c := range r.listeners {
		c <- e
	}

	if r.eventHandler != nil {
		go r.eventHandler(e)
	}
}

func (r *SyncedRegistry) registerEventChannel(channel chan *pb.Event) int {
	r.listenersMutex.Lock()
	defer r.listenersMutex.Unlock()
	r.keyCounter++
	r.listeners[r.keyCounter] = channel
	return r.keyCounter
}

func (r *SyncedRegistry) deRegisterEventChannel(key int) {
	r.listenersMutex.Lock()
	defer r.listenersMutex.Unlock()
	delete(r.listeners, key)
}
