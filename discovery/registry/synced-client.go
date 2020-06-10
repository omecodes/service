package registry

import (
	"context"
	"crypto/tls"
	"github.com/google/uuid"
	"github.com/omecodes/common"
	"github.com/omecodes/common/clone"
	"github.com/omecodes/common/errors"
	"github.com/omecodes/common/log"
	pb2 "github.com/omecodes/common/proto/service"
	"github.com/omecodes/service/discovery"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"io"
	"sync"
	"time"
)

type EventHandler interface {
	Handle(*pb2.Event)
}

type SyncedClient struct {
	servicesLock sync.Mutex
	handlersLock sync.Mutex
	syncMutex    sync.Mutex

	services map[string]*pb2.Info
	client   pb2.RegistryClient

	tlsConfig     *tls.Config
	conn          *grpc.ClientConn
	serverAddress string
	eventHandlers map[string]discovery.RegistryEventHandler
	stopRequested bool
	syncing       bool

	connectionAttempts int
	unconnectedTime    time.Time

	sendCloseSignal chan bool
	outboundStream  chan *pb2.Event
}

func (r *SyncedClient) RegisterService(i *pb2.Info, action pb2.ActionOnRegisterExistingService) (string, error) {
	done := false

	result := make(chan string, 2)
	var regID string
	regID = r.RegisterEventHandler(discovery.NewRegistryEventHandlerFunc(func(event *pb2.Event) {
		if done {
			return
		}

		if event.Name == discovery.GenerateID(i.Namespace, i.Name) && (event.Type == pb2.EventType_Update || event.Type == pb2.EventType_Register) {
			r.DeregisterEventHandler(regID)
			result <- event.Namespace + event.Name
		}
	}))

	r.outboundStream <- &pb2.Event{
		Type:               pb2.EventType_Register,
		Namespace:          i.Namespace,
		Name:               discovery.GenerateID(i.Namespace, i.Name),
		Info:               i,
		OnRegisterExisting: action,
	}

	timeout := time.Second * 3

	select {
	case id := <-result:
		return id, nil

	case <-time.After(timeout):
		done = true
		log.Info("registration timed out", log.Field("duration", timeout))
		return "", errors.New("time out")
	}
}

func (r *SyncedClient) DeregisterService(id string, nodes ...string) error {
	done := false
	result := make(chan bool, 1)

	var regID string
	regID = r.RegisterEventHandler(discovery.NewRegistryEventHandlerFunc(func(event *pb2.Event) {
		if done {
			return
		}
		if event.Name == id && (event.Type == pb2.EventType_DeRegister || event.Type == pb2.EventType_DeRegisterNode) {
			r.DeregisterEventHandler(regID)
			result <- true
		}
	}))
	ev := &pb2.Event{
		Type: pb2.EventType_DeRegister,
		Name: id,
	}
	if len(nodes) > 0 {
		ev.Type = pb2.EventType_DeRegisterNode
	}
	r.outboundStream <- ev

	select {
	case _ = <-result:
		return nil

	case <-time.After(time.Second * 3):
		done = true
		return errors.New("time out")
	}
}

func (r *SyncedClient) GetService(id string) (*pb2.Info, error) {
	info := r.get(id)
	if info != nil {
		return info, nil
	}

	rsp, err := r.client.Get(context.Background(), &pb2.GetRequest{
		RegistryId: id,
	})
	if err != nil {
		return nil, err
	}

	r.saveService(rsp.Info)
	return rsp.Info, nil
}

func (r *SyncedClient) GetNode(id string, nodeName string) (*pb2.Node, error) {
	info, err := r.GetService(id)
	if err != nil {
		return nil, err
	}

	for _, node := range info.Nodes {
		if node.Name == nodeName {
			return node, nil
		}
	}

	return nil, errors.NotFound
}

func (r *SyncedClient) Certificate(id string) ([]byte, error) {
	r.servicesLock.Lock()
	defer r.servicesLock.Unlock()

	for _, s := range r.services {
		if id == discovery.GenerateID(s.Namespace, s.Name) {
			strCert, found := s.Meta[common.MetaServiceCertificate]
			if !found {
				return nil, errors.NotFound
			}
			return []byte(strCert), nil
		}
	}
	return nil, errors.NotFound
}

func (r *SyncedClient) ConnectionInfo(id string, protocol pb2.Protocol) (*pb2.ConnectionInfo, error) {
	r.servicesLock.Lock()
	defer r.servicesLock.Unlock()

	ci := new(pb2.ConnectionInfo)

	for _, s := range r.services {
		if id == discovery.GenerateID(s.Namespace, s.Name) {
			for _, n := range s.Nodes {
				if protocol == n.Protocol {
					ci.Address = n.Address
					strCert, found := s.Meta["certificate"]
					if !found {
						return ci, nil
					}
					ci.Certificate = []byte(strCert)
					return ci, nil
				}
			}
		}
	}
	return nil, errors.NotFound
}

func (r *SyncedClient) RegisterEventHandler(h discovery.RegistryEventHandler) string {
	r.handlersLock.Lock()
	defer r.handlersLock.Unlock()
	hid := uuid.New().String()
	r.eventHandlers[hid] = h
	return hid
}

func (r *SyncedClient) DeregisterEventHandler(hid string) {
	r.handlersLock.Lock()
	defer r.handlersLock.Unlock()
	delete(r.eventHandlers, hid)
}

func (r *SyncedClient) GetOfType(t pb2.Type) ([]*pb2.Info, error) {
	r.servicesLock.Lock()
	defer r.servicesLock.Unlock()

	var result []*pb2.Info
	for _, s := range r.services {
		if s.Type == t {
			c := clone.New(s)
			result = append(result, c.(*pb2.Info))
		}
	}
	return result, nil
}

func (r *SyncedClient) Stop() error {
	r.stopRequested = true
	r.services = nil
	if r.conn != nil {
		return r.conn.Close()
	}
	return nil
}

func (r *SyncedClient) publishEvent(e pb2.Event) {
	r.handlersLock.Lock()
	r.handlersLock.Unlock()

	for _, handler := range r.eventHandlers {
		handler.Handle(&e)
	}
}

func (r *SyncedClient) get(name string) *pb2.Info {
	r.servicesLock.Lock()
	defer r.servicesLock.Unlock()
	info := r.services[name]
	if info != nil {
		return clone.New(info).(*pb2.Info)
	}
	return nil
}

func (r *SyncedClient) ofNamespace(namespace string) []*pb2.Info {
	r.servicesLock.Lock()
	defer r.servicesLock.Unlock()
	var services []*pb2.Info
	for _, s := range r.services {
		if namespace == "" || s.Namespace == namespace {
			services = append(services, clone.New(s).(*pb2.Info))
		}
	}
	return services
}

func (r *SyncedClient) saveService(info *pb2.Info) {
	r.servicesLock.Lock()
	defer r.servicesLock.Unlock()
	r.services[discovery.GenerateID(info.Namespace, info.Name)] = info
}

func (r *SyncedClient) deleteService(name string) {
	r.servicesLock.Lock()
	defer r.servicesLock.Unlock()
	delete(r.services, name)
}

func (r *SyncedClient) deleteServiceNode(name string, node *pb2.Info) {
	r.servicesLock.Lock()
	defer r.servicesLock.Unlock()
	service, exists := r.services[name]
	if !exists {
		return
	}

	var newNodes []*pb2.Node
	for _, oldNode := range service.Nodes {
		if oldNode.Name != node.Name {
			newNodes = append(newNodes, oldNode)
		}
	}
	service.Nodes = newNodes
}

func (r *SyncedClient) connect() error {
	if r.conn != nil && r.conn.GetState() == connectivity.Ready {
		return nil
	}

	var opts []grpc.DialOption
	if r.tlsConfig != nil {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(r.tlsConfig)))
	} else {
		opts = append(opts, grpc.WithInsecure())
	}

	var err error
	r.conn, err = grpc.Dial(r.serverAddress, opts...)
	if err != nil {
		return err
	}
	r.client = pb2.NewRegistryClient(r.conn)
	return nil
}

func (r *SyncedClient) sync() {
	if r.isSyncing() {
		return
	}
	r.setSyncing()

	for !r.stopRequested {
		err := r.connect()
		if err != nil {
			time.After(time.Second * 2)
			continue
		}
		r.work()
	}
}

func (r *SyncedClient) work() {
	r.sendCloseSignal = make(chan bool)
	r.outboundStream = make(chan *pb2.Event, 30)
	defer close(r.outboundStream)

	r.connectionAttempts++

	stream, err := r.client.Listen(context.Background())
	if err != nil {
		r.conn = nil
		if r.connectionAttempts == 1 {
			r.unconnectedTime = time.Now()
			log.Error("[Registry] unconnected", errors.Errorf("%d", status.Code(err)))
			log.Info("[Registry] trying again...")
		}
		return
	}
	defer stream.CloseSend()

	if r.connectionAttempts > 1 {
		log.Info("[Registry] connected", log.Field("after", time.Since(r.unconnectedTime).String()), log.Field("attempts", r.connectionAttempts))
	} else {
		log.Info("[Registry] connected")
	}
	r.connectionAttempts = 0

	wg := &sync.WaitGroup{}
	wg.Add(2)
	go r.recv(stream, wg)
	go r.send(stream, wg)
	wg.Wait()
}

func (r *SyncedClient) send(stream pb2.Registry_ListenClient, wg *sync.WaitGroup) {
	defer wg.Done()

	for !r.stopRequested {
		select {
		case <-r.sendCloseSignal:
			log.Info("[Registry] stop send")
			return

		case event, open := <-r.outboundStream:
			if !open {
				return
			}

			err := stream.Send(event)
			if err != nil {
				if err != io.EOF {
					log.Error("[Registry] send event", err)
				}
				return
			}
		}
	}
}

func (r *SyncedClient) recv(stream pb2.Registry_ListenClient, wg *sync.WaitGroup) {
	defer wg.Done()
	for !r.stopRequested {
		event, err := stream.Recv()
		if err != nil {
			r.sendCloseSignal <- true
			close(r.sendCloseSignal)
			if err != io.EOF {
				log.Error("[Registry] recv event", err)
			}
			return
		}

		for _, h := range r.eventHandlers {
			go h.Handle(event)
		}

		log.Info("[Registry] new event", log.Field("type", event.Type), log.Field("service", event.Name))

		switch event.Type {
		case pb2.EventType_Update, pb2.EventType_Register:
			r.saveService(event.Info)

		case pb2.EventType_DeRegister:
			r.deleteService(event.Name)

		case pb2.EventType_DeRegisterNode:
			r.deleteServiceNode(event.Name, event.Info)
		}
	}
}

func (r *SyncedClient) isSyncing() bool {
	r.syncMutex.Lock()
	defer r.syncMutex.Unlock()
	return r.syncing
}

func (r *SyncedClient) setSyncing() {
	r.syncMutex.Lock()
	defer r.syncMutex.Unlock()
	r.syncing = true
}

func (r *SyncedClient) disconnected() {
	r.services = nil
}

func NewSyncedRegistryClient(server string, tlsConfig *tls.Config) *SyncedClient {
	sc := &SyncedClient{
		services:      map[string]*pb2.Info{},
		tlsConfig:     tlsConfig,
		serverAddress: server,
		eventHandlers: map[string]discovery.RegistryEventHandler{},
	}
	go sc.sync()
	return sc
}
