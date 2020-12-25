package service

import (
	"context"
	"crypto/tls"
	"github.com/omecodes/libome/logs"
	"io"
	"sync"
	"time"

	"github.com/omecodes/common/errors"
	"github.com/omecodes/libome"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

type synchronizedStore struct {
	sync.Mutex
	store              JwtInfoStore
	serverAddress      string
	tls                *tls.Config
	conn               *grpc.ClientConn
	client             ome.TokenStoreServiceClient
	stopRequested      bool
	connectionAttempts int
	unconnectedTime    time.Time
	syncing            bool
	syncMutex          sync.Mutex
	outboundStream     chan *ome.JWTStateMessage
	inboundStream      chan *ome.JWTStateMessage
	sendCloseSignal    chan bool
}

func (s *synchronizedStore) connect() error {
	if s.conn != nil && s.conn.GetState() == connectivity.Ready {
		return nil
	}

	var opts []grpc.DialOption
	if s.tls != nil {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(s.tls)))
	} else {
		opts = append(opts, grpc.WithInsecure())
	}

	var err error
	s.conn, err = grpc.Dial(s.serverAddress, opts...)
	if err != nil {
		return err
	}
	s.client = ome.NewTokenStoreServiceClient(s.conn)
	return nil
}

func (s *synchronizedStore) sync() {
	if s.isSyncing() {
		return
	}
	s.setSyncing()

	err := s.store.DeleteAllFromService(s.serverAddress)
	if err != nil {
		logs.Error("failed to clear jwt store", logs.Err(err))
	}

	for !s.stopRequested {
		err = s.connect()
		if err != nil {
			time.After(time.Second * 2)
			continue
		}
		s.work()
		err = s.store.DeleteAllFromService(s.serverAddress)
		if err != nil {
			logs.Error("failed to clear jwt store", logs.Err(err))
		}
	}
}

func (s *synchronizedStore) work() {
	s.sendCloseSignal = make(chan bool)
	s.outboundStream = make(chan *ome.JWTStateMessage, 30)
	defer close(s.outboundStream)

	s.connectionAttempts++

	stream, err := s.client.Synchronize(context.Background())
	if err != nil {
		s.conn = nil
		if s.connectionAttempts == 1 {
			s.unconnectedTime = time.Now()
			logs.Error("[jwt store] unconnected", logs.Err(errors.Errorf("%d", status.Code(err))))
			logs.Info("[jwt store] trying again...")
		}
		return
	}
	defer stream.CloseSend()

	if s.connectionAttempts > 1 {
		logs.Info("[jwt store] connected", logs.Details("after", time.Since(s.unconnectedTime).String()), logs.Details("attempts", s.connectionAttempts))
	} else {
		logs.Info("[jwt store] connected")
	}
	s.connectionAttempts = 0

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go s.recv(stream, wg)
	// go s.send(stream, wg)
	wg.Wait()
}

func (s *synchronizedStore) send(stream ome.TokenStoreService_SynchronizeClient, wg *sync.WaitGroup) {
	defer wg.Done()

	for !s.stopRequested {
		select {
		case <-s.sendCloseSignal:
			logs.Info("[jwt store] stop send")
			return

		case event, open := <-s.outboundStream:
			if !open {
				return
			}

			err := stream.Send(event)
			if err != nil {
				if err != io.EOF {
					logs.Error("[jwt store] send event", logs.Err(err))
				}
				return
			}
		}
	}
}

func (s *synchronizedStore) recv(stream ome.TokenStoreService_SynchronizeClient, wg *sync.WaitGroup) {
	defer wg.Done()
	for !s.stopRequested {
		event, err := stream.Recv()
		if err != nil {
			s.sendCloseSignal <- true
			close(s.sendCloseSignal)
			if err != io.EOF {
				logs.Error("[jwt store] recv event", logs.Err(err))
			}
			return
		}

		logs.Info("[jwt store] new event", logs.Details("action", event.State), logs.Details("id", event.Info.Jti))

		switch event.State {
		case ome.JWTState_Valid:
			err = s.store.Save(s.serverAddress, event.Info)
			if err != nil {
				logs.Error("[jwt store] failed to save jwt info", logs.Err(err), logs.Details("id", event.Info.Jti))
			}

		case ome.JWTState_Revoked:
			err = s.store.Delete(event.Info.Jti)
			if err != nil {
				logs.Error("failed to delete jwt info", logs.Err(err), logs.Details("id", event.Info.Jti))
			}
		}
	}
}

func (s *synchronizedStore) isSyncing() bool {
	s.syncMutex.Lock()
	defer s.syncMutex.Unlock()
	return s.syncing
}

func (s *synchronizedStore) setSyncing() {
	s.syncMutex.Lock()
	defer s.syncMutex.Unlock()
	s.syncing = true
}

func (s *synchronizedStore) getJwtState(jti string) (ome.JWTState, error) {
	info, err := s.store.Get(jti)
	if err != nil {
		return 0, err
	}

	now := time.Now().Unix()
	if info.Nbf > now {
		return ome.JWTState_NotEffective, errors.New("jwt not effective")
	}

	if info.Exp != -1 && info.Exp < now {
		return ome.JWTState_Expired, errors.New("jwt expired")
	}

	return ome.JWTState_Valid, nil
}

func (s *synchronizedStore) State(jti string) (ome.JWTState, error) {
	return s.getJwtState(jti)
}

func (s *synchronizedStore) Close() error {
	s.stopRequested = true
	return nil
}

func NewSyncedStore(serverAddress string, tls *tls.Config, store JwtInfoStore) *synchronizedStore {
	syncedStore := &synchronizedStore{
		serverAddress: serverAddress,
		tls:           tls,
		store:         store,
	}
	_ = store.Clear()
	go syncedStore.sync()
	return syncedStore
}
