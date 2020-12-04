package registry

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/omecodes/bome"
	"github.com/omecodes/common/errors"
	"github.com/omecodes/common/netx"
	"github.com/omecodes/common/utils/log"
	"github.com/omecodes/libome"
	"github.com/omecodes/zebou"
	"net"
	"path/filepath"
	"strings"
	"sync"
)

type ServerConfig struct {
	Name         string
	StoreDir     string
	BindAddress  string
	CertFilename string
	KeyFilename  string
}

type msgServer struct {
	sync.Mutex
	handlers map[string]ome.EventHandler
	listener net.Listener
	hub      *zebou.Hub
	store    *bome.DoubleMap
	name     string
}

func (s *msgServer) NewClient(ctx context.Context, peer *zebou.PeerInfo) {
	if peer != nil {
		log.Info("new client connected", log.Field("conn_id", peer.ID), log.Field("addr", peer.Address))
	} else {
		log.Info("new client connected")
	}

	c, err := s.store.GetAll()
	if err != nil {
		log.Error("could not load services list from store", log.Err(err))
		return
	}

	defer func() {
		if err := c.Close(); err != nil {
			log.Error("failed to close cursor", log.Err(err))
		}
	}()

	for c.HasNext() {
		var info ome.ServiceInfo
		o, err := c.Next()
		if err != nil {
			log.Error("failed to parse service info", log.Err(err))
			return
		}

		entry := o.(*bome.DoubleMapEntry)

		err = zebou.Send(ctx, &zebou.ZeMsg{
			Type:    ome.RegistryEventType_Register.String(),
			Id:      info.Id,
			Encoded: []byte(entry.Value),
		})
		if err != nil {
			log.Error("could not send message", log.Err(err))
			return
		}
	}
}

func (s *msgServer) ClientQuit(ctx context.Context, peer *zebou.PeerInfo) {
	log.Info("client disconnected", log.Field("conn_id", peer.ID), log.Field("addr", peer.Address))
	services, err := s.getFromClient(peer.ID)
	if err != nil {
		log.Error("could not get client registered services", log.Err(err))
		return
	}

	err = s.store.DeleteAllMatchingFirstKey(peer.ID)
	if err != nil {
		log.Error("could not delete client registered services", log.Err(err))
		return
	}

	for _, info := range services {
		encoded, err := json.Marshal(info)
		if err != nil {
			log.Error("failed to encode service info", log.Err(err))
			return
		}

		s.hub.Broadcast(ctx, &zebou.ZeMsg{
			Type:    ome.RegistryEventType_DeRegister.String(),
			Id:      info.Id,
			Encoded: encoded,
		})
	}
}

func (s *msgServer) getFromClient(id string) ([]*ome.ServiceInfo, error) {
	c, err := s.store.GetForFirst(id)
	if err != nil {
		log.Error("failed to get registered nodes", log.Field("conn_id", id))
		return nil, err
	}

	defer func() {
		if err := c.Close(); err != nil {
			log.Error("failed to close cursor", log.Err(err))
		}
	}()

	var result []*ome.ServiceInfo
	for c.HasNext() {
		o, err := c.Next()
		if err != nil {
			return nil, err
		}

		entry := o.(bome.MapEntry)

		var info ome.ServiceInfo
		err = json.Unmarshal([]byte(entry.Value), &info)
		if err != nil {
			return nil, err
		}
		result = append(result, &info)
	}
	return result, nil
}

func (s *msgServer) OnMessage(ctx context.Context, msg *zebou.ZeMsg) {
	peer := zebou.Peer(ctx)
	go s.hub.Broadcast(ctx, msg)

	switch msg.Type {
	case ome.RegistryEventType_Update.String(), ome.RegistryEventType_Register.String():
		entry := &bome.DoubleMapEntry{
			FirstKey:  peer.ID,
			SecondKey: msg.Id,
			Value:     string(msg.Encoded),
		}
		err := s.store.Save(entry)
		if err != nil {
			log.Error("failed to store service info", log.Err(err))
			return
		}
		log.Info(msg.Type, log.Field("service", msg.Id))

		info := new(ome.ServiceInfo)
		err = json.Unmarshal(msg.Encoded, &info)
		if err != nil {
			log.Error("failed to decode service info", log.Err(err))
			return
		}
		event := &ome.RegistryEvent{
			ServiceId: msg.Id,
			Info:      info,
		}
		event.Type = ome.RegistryEventType(ome.RegistryEventType_value[msg.Type])
		s.notifyEvent(event)

	case ome.RegistryEventType_DeRegister.String():
		err := s.store.Delete(peer.ID, msg.Id)
		if err != nil {
			log.Error("could not delete service info", log.Err(err), log.Field("service", msg.Id))
			return
		}

		log.Info(msg.Type, log.Field("service", msg.Id))
		s.notifyEvent(&ome.RegistryEvent{
			Type:      ome.RegistryEventType_DeRegister,
			ServiceId: msg.Id,
		})

	case ome.RegistryEventType_DeRegisterNode.String():

		value, err := s.store.Get(peer.ID, msg.Id)
		if err != nil {
			log.Error("failed to read service info", log.Err(err), log.Field("service", msg.Id))
			return
		}

		var info ome.ServiceInfo
		err = json.Unmarshal([]byte(value), &info)
		if err != nil {
			log.Error("failed to decode service info", log.Err(err))
			return
		}

		nodeId := string(msg.Encoded)
		var newNodes []*ome.Node
		for _, node := range info.Nodes {
			if node.Id != nodeId {
				newNodes = append(newNodes, node)
			}
		}
		info.Nodes = newNodes

		newEncoded, err := json.Marshal(&info)
		if err != nil {
			log.Error("failed to encode service info", log.Err(err))
			return
		}

		entry := &bome.DoubleMapEntry{
			FirstKey:  peer.ID,
			SecondKey: msg.Id,
			Value:     string(newEncoded),
		}
		err = s.store.Save(entry)
		if err != nil {
			log.Error("failed to update service info", log.Err(err), log.Field("service", msg.Id))
			return
		}

		log.Info(msg.Type, log.Field("nodes", string(msg.Encoded)))

		s.notifyEvent(&ome.RegistryEvent{
			Type:      ome.RegistryEventType_DeRegisterNode,
			ServiceId: msg.Id,
			Info:      &info,
		})

	default:
		log.Info("received unsupported msg type", log.Field("type", msg.Type))
	}
}

func (s *msgServer) RegisterService(i *ome.ServiceInfo) error {
	encoded, err := json.Marshal(i)
	if err != nil {
		log.Error("failed to json encode i")
		return err
	}

	err = s.store.Save(&bome.DoubleMapEntry{
		FirstKey:  s.name,
		SecondKey: i.Id,
		Value:     string(encoded),
	})
	if err != nil {
		return err
	}

	msg := &zebou.ZeMsg{
		Type:    ome.RegistryEventType_Register.String(),
		Id:      i.Id,
		Encoded: encoded,
	}

	s.hub.Broadcast(context.Background(), msg)
	s.notifyEvent(&ome.RegistryEvent{
		Type:      ome.RegistryEventType_Register,
		ServiceId: i.Id,
		Info:      i,
	})
	return nil
}

func (s *msgServer) DeregisterService(id string, nodes ...string) error {
	msg := &zebou.ZeMsg{
		Id: id,
	}

	if len(nodes) > 0 {
		var info ome.ServiceInfo
		encoded, err := s.store.Get(s.name, id)
		if err != nil {
			return err
		}

		err = json.Unmarshal([]byte(encoded), &info)
		if err != nil {
			return err
		}

		var newNodes []*ome.Node
		for _, node := range info.Nodes {
			deleted := true
			for _, nodeId := range nodes {
				if nodeId == node.Id {
					deleted = false
					break
				}
			}

			if !deleted {
				newNodes = append(newNodes, node)
			}
		}

		info.Nodes = newNodes

		newEncodedBytes, err := json.Marshal(&info)
		if err != nil {
			return err
		}

		err = s.store.Save(&bome.DoubleMapEntry{
			FirstKey:  s.name,
			SecondKey: id,
			Value:     string(newEncodedBytes),
		})
		if err != nil {
			return err
		}

		msg.Encoded = []byte(strings.Join(nodes, "|"))
		msg.Type = ome.RegistryEventType_DeRegisterNode.String()
		s.hub.Broadcast(context.Background(), msg)
		ev := &ome.RegistryEvent{
			Type:      ome.RegistryEventType_DeRegisterNode,
			ServiceId: fmt.Sprintf("%s:%s", id, encoded),
		}
		s.notifyEvent(ev)

	} else {
		err := s.store.Delete(s.name, id)
		if err != nil {
			return err
		}

		msg.Type = ome.RegistryEventType_DeRegister.String()
		msg.Id = id

		s.hub.Broadcast(context.Background(), msg)
		ev := &ome.RegistryEvent{
			Type:      ome.RegistryEventType_DeRegister,
			ServiceId: id,
		}
		s.notifyEvent(ev)
	}
	return nil
}

func (s *msgServer) GetService(id string) (*ome.ServiceInfo, error) {
	var info ome.ServiceInfo
	encoded, err := s.store.Get(s.name, id)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal([]byte(encoded), &info)
	return &info, err
}

func (s *msgServer) GetNode(id string, nodeName string) (*ome.Node, error) {
	info, err := s.GetService(id)
	if err != nil {
		return nil, err
	}

	for _, node := range info.Nodes {
		if node.Id == nodeName {
			return node, nil
		}
	}

	return nil, errors.NotFound
}

func (s *msgServer) Certificate(id string) ([]byte, error) {
	info, err := s.GetService(id)
	if err != nil {
		return nil, err
	}

	strCert, found := info.Meta["certificate"]
	if !found {
		return nil, errors.NotFound
	}
	return []byte(strCert), nil
}

func (s *msgServer) ConnectionInfo(id string, protocol ome.Protocol) (*ome.ConnectionInfo, error) {
	info, err := s.GetService(id)
	if err != nil {
		return nil, err
	}

	for _, n := range info.Nodes {
		if protocol == n.Protocol {
			ci := new(ome.ConnectionInfo)
			ci.Address = n.Address
			strCert, found := info.Meta["certificate"]
			if !found {
				return ci, nil
			}
			ci.Certificate = []byte(strCert)
			return ci, nil
		}
	}

	return nil, errors.NotFound
}

func (s *msgServer) RegisterEventHandler(h ome.EventHandler) string {
	s.Lock()
	defer s.Unlock()
	hid := uuid.New().String()
	s.handlers[hid] = h
	return hid
}

func (s *msgServer) DeregisterEventHandler(hid string) {
	s.Lock()
	defer s.Unlock()
	delete(s.handlers, hid)
}

func (s *msgServer) GetOfType(t ome.ServiceType) ([]*ome.ServiceInfo, error) {
	var infoList []*ome.ServiceInfo
	c, err := s.store.GetAll()
	if err != nil {
		return nil, err
	}

	defer func() {
		if err := c.Close(); err != nil {
			log.Error("failed to close cursor", log.Err(err))
		}
	}()

	for c.HasNext() {
		o, err := c.Next()
		if err != nil {
			return infoList, err
		}

		entry := o.(*bome.DoubleMapEntry)

		var info ome.ServiceInfo
		err = json.Unmarshal([]byte(entry.Value), &info)
		if err != nil {
			return infoList, err
		}

		if info.Type == t {
			infoList = append(infoList, nil)
		}
	}
	return infoList, nil
}

func (s *msgServer) FirstOfType(t ome.ServiceType) (*ome.ServiceInfo, error) {
	c, err := s.store.GetAll()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := c.Close(); err != nil {
			log.Error("failed to close cursor", log.Err(err))
		}
	}()

	for c.HasNext() {
		o, err := c.Next()
		if err != nil {
			return nil, err
		}

		entry := o.(*bome.DoubleMapEntry)

		var info ome.ServiceInfo
		err = json.Unmarshal([]byte(entry.Value), &info)
		if err != nil {
			return nil, err
		}

		if info.Type == t {
			return &info, nil
		}
	}
	return nil, errors.NotFound
}

func (s *msgServer) Stop() error {
	_ = s.hub.Stop()
	return s.listener.Close()
}

func (s *msgServer) notifyEvent(e *ome.RegistryEvent) {
	s.Lock()
	defer s.Unlock()

	for _, h := range s.handlers {
		go h.Handle(e)
	}
}

func Serve(configs *ServerConfig) (ome.Registry, error) {
	s := new(msgServer)
	var opts []netx.ListenOption

	if configs.CertFilename != "" {
		opts = append(opts, netx.Secure(configs.CertFilename, configs.KeyFilename))
	}

	s.name = configs.Name
	var err error
	s.listener, err = netx.Listen(configs.BindAddress, opts...)
	if err != nil {
		return nil, err
	}

	log.Info("[discovery] starting gRPC server", log.Field("at", s.listener.Addr()))

	db, err := sql.Open("sqlite3", filepath.Join(configs.StoreDir, "registry.db"))
	if err != nil {
		log.Error("could not open registry database", log.Err(err))
		return nil, err
	}

	s.store, err = bome.NewDoubleMap(db, bome.SQLite3, "registry")
	if err != nil {
		return nil, err
	}

	err = s.store.Clear()
	if err != nil {
		log.Error("failed to reset registry store", log.Err(err))
		return nil, err
	}

	s.hub, err = zebou.Serve(s.listener, s)
	if err != nil {
		return nil, err
	}

	s.handlers = map[string]ome.EventHandler{}

	return s, nil
}
