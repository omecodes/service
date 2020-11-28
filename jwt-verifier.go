package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/omecodes/common/errors"
	"github.com/omecodes/common/utils/log"
	"github.com/omecodes/libome"
	"github.com/omecodes/libome/crypt"
)

type syncedVerifier struct {
	sync.Mutex
	registry          ome.Registry
	storesMutex       sync.Mutex
	tokenVerifiers    map[string]ome.TokenVerifier
	syncedStores      map[string]*synchronizedStore
	store             JwtInfoStore
	storesInitialized bool
	tlsConfig         *tls.Config
}

func (j *syncedVerifier) Verify(ctx context.Context, t *ome.JWT) (ome.JWTState, error) {
	j.initStores()
	issuer := t.Claims.Iss

	verifier := j.getJwtVerifier(issuer)
	if verifier == nil {
		parts := strings.Split(issuer, "@")
		nodeName := parts[0]
		serviceName := parts[1]

		s, err := j.registry.GetNode(serviceName, nodeName)
		if err != nil {
			return 0, errors.Forbidden
		}

		encodedKey := s.Meta[ome.MetaTokenVerifyingKey]
		key, _, err := crypt.PEMDecodePublicKey([]byte(encodedKey))
		if err != nil {
			return 0, err
		}

		verifier = ome.NewTokenVerifier(key.(*ecdsa.PublicKey))
		j.saveJwtVerifier(t.Claims.Iss, verifier)
	}

	state, err := verifier.Verify(ctx, t)
	if err != nil {
		return 0, fmt.Errorf("[jwt verifier] failed to verify to token: %s", errors.Internal)
	}

	if state != ome.JWTState_Valid {
		return 0, errors.Forbidden
	}

	if t.Claims.VerificationInfo != nil {
		jwtStore := j.getStore(t.Claims.VerificationInfo.StateService)

		if jwtStore == nil {
			parts := strings.Split(t.Claims.VerificationInfo.StateService, "@")
			nodeName := parts[0]
			serviceName := parts[1]

			node, err := j.registry.GetNode(serviceName, nodeName)
			if err != nil {
				log.Error("[jwt verifier] failed to get node info", log.Err(err), log.Field("service", serviceName), log.Field("node", nodeName))
				return 0, errors.Forbidden
			}

			jwtStore = NewSyncedStore(node.Address, j.tlsConfig, j.store)
			j.saveStore(t.Claims.VerificationInfo.StateService, jwtStore)
		}

		state, err = jwtStore.State(t.Claims.Jti)
		if err != nil {
			return state, err
		}

		if state != ome.JWTState_Valid {
			return 0, errors.Forbidden
		}
	}
	return ome.JWTState_Valid, nil
}

func (j *syncedVerifier) VerifyJWT(ctx context.Context, jwt string) (ome.JWTState, error) {
	j.initStores()

	t, err := ome.ParseJWT(jwt)
	if err != nil {
		return ome.JWTState_NotValid, err
	}

	return j.Verify(ctx, t)
}

func (j *syncedVerifier) saveJwtVerifier(name string, v ome.TokenVerifier) {
	j.Lock()
	defer j.Unlock()
	j.tokenVerifiers[name] = v
}

func (j *syncedVerifier) getJwtVerifier(name string) ome.TokenVerifier {
	j.Lock()
	defer j.Unlock()
	return j.tokenVerifiers[name]
}

func (j *syncedVerifier) getStore(name string) *synchronizedStore {
	j.Lock()
	defer j.Unlock()
	return j.syncedStores[name]
}

func (j *syncedVerifier) saveStore(name string, s *synchronizedStore) {
	j.Lock()
	defer j.Unlock()
	j.syncedStores[name] = s
}

func (j *syncedVerifier) initStores() {
	j.Lock()
	defer j.Unlock()

	if j.storesInitialized {
		return
	}
	j.storesInitialized = true

	log.Info("[jwt verifier] initializing token stores")
	infos, err := j.registry.GetOfType(ome.ServiceType_TokenStore)
	if err != nil {
		log.Error("[jwt verifier] could not load token stores info", log.Err(err))
		return
	}

	for _, info := range infos {
		for _, node := range info.Nodes {
			if node.Protocol == ome.Protocol_Grpc {
				storeName := fmt.Sprintf("%s@%s", node.Id, info.Id)
				jwtStore := NewSyncedStore(node.Address, j.tlsConfig, j.store)
				j.syncedStores[storeName] = jwtStore
			}
		}
	}
	<-time.After(time.Second)
}

func NewJwtVerifier(tlsConfig *tls.Config, registry ome.Registry, store JwtInfoStore) ome.TokenVerifier {
	verifier := &syncedVerifier{
		tokenVerifiers: map[string]ome.TokenVerifier{},
		syncedStores:   map[string]*synchronizedStore{},
		store:          store,
		registry:       registry,
		tlsConfig:      tlsConfig,
	}

	if store == nil {
		verifier.store = NewMemInfoStore()
	}
	return verifier
}
