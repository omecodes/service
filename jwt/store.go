package jwt

import (
	"context"
	"crypto/tls"
	"github.com/google/uuid"
	"github.com/omecodes/common/errors"
	"github.com/omecodes/common/log"
	"github.com/omecodes/common/persist/dict"
	authpb "github.com/omecodes/common/proto/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"io"
	"sync"
	"time"
)

type SyncedStore struct {
	sync.Mutex
	store                     dict.Dict
	serverAddress             string
	tls                       *tls.Config
	conn                      *grpc.ClientConn
	jwtRevokedHandlerFuncList map[string]RevokedHandlerFunc
	client                    authpb.TokenStoreServiceClient
	stopRequested             bool
	connectionAttempts        int
	unconnectedTime           time.Time
	syncing                   bool
	syncMutex                 sync.Mutex
	outboundStream            chan *authpb.SyncMessage
	inboundStream             chan *authpb.SyncMessage
	sendCloseSignal           chan bool
}

func (s *SyncedStore) connect() error {
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
	s.client = authpb.NewTokenStoreServiceClient(s.conn)
	return nil
}

func (s *SyncedStore) sync() {
	if s.isSyncing() {
		return
	}
	s.setSyncing()

	for !s.stopRequested {
		err := s.connect()
		if err != nil {
			time.After(time.Second * 2)
			continue
		}
		s.work()
	}
}

func (s *SyncedStore) work() {
	s.sendCloseSignal = make(chan bool)
	s.outboundStream = make(chan *authpb.SyncMessage, 30)
	defer close(s.outboundStream)

	s.connectionAttempts++

	stream, err := s.client.Sync(context.Background())
	if err != nil {
		s.conn = nil
		if s.connectionAttempts == 1 {
			s.unconnectedTime = time.Now()
			log.Error("[jwt store] unconnected", errors.Errorf("%d", status.Code(err)))
			log.Info("[jwt store] trying again...")
		}
		return
	}
	defer stream.CloseSend()

	if s.connectionAttempts > 1 {
		log.Info("[jwt store] connected", log.Field("after", time.Since(s.unconnectedTime).String()), log.Field("attempts", s.connectionAttempts))
	} else {
		log.Info("[jwt store] connected")
	}
	s.connectionAttempts = 0

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go s.recv(stream, wg)
	// go s.send(stream, wg)
	wg.Wait()
}

func (s *SyncedStore) send(stream authpb.TokenStoreService_SyncClient, wg *sync.WaitGroup) {
	defer wg.Done()

	for !s.stopRequested {
		select {
		case <-s.sendCloseSignal:
			log.Info("[jwt store] stop send")
			return

		case event, open := <-s.outboundStream:
			if !open {
				return
			}

			err := stream.Send(event)
			if err != nil {
				if err != io.EOF {
					log.Error("[jwt store] send event", err)
				}
				return
			}
		}
	}
}

func (s *SyncedStore) recv(stream authpb.TokenStoreService_SyncClient, wg *sync.WaitGroup) {
	defer wg.Done()
	for !s.stopRequested {
		event, err := stream.Recv()
		if err != nil {
			s.sendCloseSignal <- true
			close(s.sendCloseSignal)
			if err != io.EOF {
				log.Error("[jwt store] recv event", err)
			}
			return
		}

		log.Info("[jwt store] new event", log.Field("action", event.Action), log.Field("id", event.Info.Jti))

		switch event.Action {
		case authpb.EventAction_Save:
			err = s.store.Save(event.Info.Jti, event.Info)
			if err != nil {
				log.Error("[jwt store] failed to save jwt info", err, log.Field("id", event.Info.Jti))
			}

		case authpb.EventAction_Delete:
			err = s.store.Delete(event.Info.Jti)
			if err != nil {
				log.Error("failed to delete jwt info", err, log.Field("id", event.Info.Jti))
			}
		}
	}
}

func (s *SyncedStore) isSyncing() bool {
	s.syncMutex.Lock()
	defer s.syncMutex.Unlock()
	return s.syncing
}

func (s *SyncedStore) setSyncing() {
	s.syncMutex.Lock()
	defer s.syncMutex.Unlock()
	s.syncing = true
}

func (s *SyncedStore) getJwtState(jti string) (authpb.JWTState, error) {
	info := new(authpb.JwtInfo)
	err := s.store.Read(jti, info)
	if err != nil {
		return 0, err
	}

	now := time.Now().Unix()
	if info.Nbf > now {
		return authpb.JWTState_NOT_EFFECTIVE, errors.New("jwt not effective")
	}

	if info.Exp != -1 && info.Exp < now {
		return authpb.JWTState_EXPIRED, errors.New("jwt expired")
	}

	return authpb.JWTState_VALID, nil
}

func (s *SyncedStore) State(jti string) (authpb.JWTState, error) {
	return s.getJwtState(jti)
}

func (s *SyncedStore) AddJwtRevokedEventHandler(f RevokedHandlerFunc) string {
	s.Lock()
	defer s.Unlock()
	id := uuid.New().String()
	s.jwtRevokedHandlerFuncList[id] = f
	return id
}

func (s *SyncedStore) DeleteJwtRevokedEventHandler(id string) {
	s.Lock()
	defer s.Unlock()
	delete(s.jwtRevokedHandlerFuncList, id)
}

func (s *SyncedStore) Close() error {
	s.stopRequested = true
	return s.store.Close()
}

func NewSyncedStore(server string, tls *tls.Config, store dict.Dict) *SyncedStore {
	syncedStore := &SyncedStore{
		serverAddress:             server,
		tls:                       tls,
		store:                     store,
		jwtRevokedHandlerFuncList: map[string]RevokedHandlerFunc{},
	}

	_ = store.Clear()
	go syncedStore.sync()
	return syncedStore
}
