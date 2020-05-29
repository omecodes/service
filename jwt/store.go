package jwt

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/zoenion/common/errors"
	"github.com/zoenion/common/log"
	"github.com/zoenion/common/persist/dict"
	authpb "github.com/zoenion/common/proto/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
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
}

func (s *SyncedStore) connect() (err error) {
	if s.conn != nil && s.conn.GetState() == connectivity.Ready {
		return nil
	}
	if s.tls != nil {
		s.conn, err = grpc.Dial(s.serverAddress, grpc.WithTransportCredentials(credentials.NewTLS(s.tls)))
	} else {
		s.conn, err = grpc.Dial(s.serverAddress, grpc.WithInsecure())
	}
	if err == nil {
		go s.connected()
	}
	return err
}

func (s *SyncedStore) connected() {
	client := authpb.NewTokenStoreServiceClient(s.conn)
	stream, err := client.Listen(context.Background(), &authpb.ListenRequest{})
	if err != nil {
		log.Error("could not listen to jwt events", err)
		return
	}
	defer stream.CloseSend()
	for {
		event, err := stream.Recv()
		if err != nil {
			//log.Printf("received error while read jwt events stream: %s\n", err)
			return
		}
		switch event.Action {
		case authpb.EventAction_Save:
			_ = s.saveJwtInfo(event.Info)
		case authpb.EventAction_Delete:
			_ = s.deleteJwtInfo(event.Info.Jti)
		}
	}
}

func (s *SyncedStore) saveJwtInfo(i *authpb.JwtInfo) error {
	marshaled, err := json.Marshal(i)
	if err != nil {
		return err
	}
	return s.store.Save(i.Jti, string(marshaled))
}

func (s *SyncedStore) deleteJwtInfo(jti string) error {
	return s.store.Delete(jti)
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

	if info.Exp < now {
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

func NewSyncedStore(server string, tls *tls.Config, store dict.Dict) *SyncedStore {
	return &SyncedStore{
		serverAddress:             server,
		tls:                       tls,
		store:                     store,
		jwtRevokedHandlerFuncList: map[string]RevokedHandlerFunc{},
	}
}
