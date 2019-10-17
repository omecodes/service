package service

import (
	"context"
	"crypto/tls"
	"fmt"
	pb "github.com/zoenion/service/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
	"io"
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

	log.Println("starting Registry.gRPC at", listener.Addr())
	go srv.Serve(listener)
	return nil
}

func (r *SyncedRegistry) Register(ctx context.Context, in *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	peerAddress := "unknown"
	p, ok := peer.FromContext(ctx)
	if ok {
		peerAddress = p.Addr.String()
	}

	r.saveService(in.Service)
	registryID := in.Service.Namespace + ":" + in.Service.Name
	result := &pb.RegisterResponse{RegistryId: registryID}
	log.Printf("[Registry Server]:\tRegistered %s@%s\n", registryID, peerAddress)
	return result, nil
}

func (r *SyncedRegistry) Deregister(ctx context.Context, in *pb.DeregisterRequest) (*pb.DeregisterResponse, error) {
	peerAddress := "unknown"
	p, ok := peer.FromContext(ctx)
	if ok {
		peerAddress = p.Addr.String()
	}
	r.deleteService(in.RegistryId)
	log.Printf("[Registry Server]:\tDe-registered %s@%s\n", in.RegistryId, peerAddress)
	//r.deRegisterEventChannelByName(in.RegistryId)
	return &pb.DeregisterResponse{}, nil
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
	peerAddress := "unknown"
	p, ok := peer.FromContext(stream.Context())
	if ok {
		peerAddress = p.Addr.String()
	}

	log.Printf("[Registry Server]:\tSyncing with client from client@%s\n", peerAddress)
	list := r.ofNamespace(in.Namespace)

	for _, i := range list {
		ev := &pb.Event{
			Type: pb.EventType_Registered,
			Name: fmt.Sprintf("%s:%s", i.Namespace, i.Name),
			Info: i,
		}

		err := stream.Send(ev)
		if err != nil {
			log.Printf("[Registry Server]:\tCould not send event to client@%s: %s\n", peerAddress, err)
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
			log.Printf("[Registry Server]:\t Closed sync stream with client client@%s\n", peerAddress)
			return io.EOF
		}

		err := stream.Send(e)
		if err != nil {
			log.Printf("[Registry Server]:\tCould not send event to client at client@%s: %s\n", peerAddress, err)
			return io.EOF
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
