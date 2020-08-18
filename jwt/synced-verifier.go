package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/omecodes/common/dao/dict"
	"github.com/omecodes/common/env/app"
	"github.com/omecodes/common/errors"
	"github.com/omecodes/common/utils/codec"
	"github.com/omecodes/common/utils/log"
	ome2 "github.com/omecodes/libome"
	"github.com/omecodes/libome/crypt"
	"github.com/omecodes/libome/proto/auth"
	pb2 "github.com/omecodes/libome/proto/service"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type syncedVerifier struct {
	sync.Mutex
	registry          pb2.Registry
	storesMutex       sync.Mutex
	tokenVerifiers    map[string]authpb.TokenVerifier
	syncedStores      map[string]*SyncedStore
	CaCert            *x509.Certificate
	serviceCert       *x509.Certificate
	serviceKey        crypto.PrivateKey
	cacheDir          string
	storesInitialized bool
}

func (j *syncedVerifier) Verify(ctx context.Context, t *authpb.JWT) (authpb.JWTState, error) {

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

		encodedKey := s.Meta[ome2.MetaTokenVerifyingKey]
		key, _, err := crypt.PEMDecodePublicKey([]byte(encodedKey))
		if err != nil {
			return 0, err
		}

		verifier = authpb.NewTokenVerifier(key.(*ecdsa.PublicKey))
		j.saveJwtVerifier(t.Claims.Iss, verifier)
	}

	state, err := verifier.Verify(ctx, t)
	if err != nil {
		return 0, fmt.Errorf("[jwt verifier] failed to verify to token: %s", errors.Internal)
	}

	if state != authpb.JWTState_VALID {
		return 0, errors.Forbidden
	}

	if t.Claims.JwtStore != "" {
		jwtStore := j.getStore(t.Claims.JwtStore)

		if jwtStore == nil {
			parts := strings.Split(t.Claims.JwtStore, "@")
			nodeName := parts[0]
			serviceName := parts[1]

			node, err := j.registry.GetNode(serviceName, nodeName)
			if err != nil {
				log.Error("[jwt verifier] failed to get node info", log.Err(err), log.Field("service", serviceName), log.Field("node", nodeName))
				return 0, errors.Forbidden
			}

			dictStore, err := dict.New(app.SQLiteConfig(filepath.Join(j.cacheDir, "jwt-store.db")), "jwt", codec.Default)
			if err != nil {
				return 0, errors.Internal
			}

			CAPool := x509.NewCertPool()
			CAPool.AddCert(j.CaCert)
			tlsConfig := &tls.Config{
				RootCAs: CAPool,
				Certificates: []tls.Certificate{{
					Certificate: [][]byte{j.serviceCert.Raw},
					PrivateKey:  j.serviceKey,
				}},
			}

			jwtStore = NewSyncedStore(node.Address, tlsConfig, dictStore)
			j.saveStore(t.Claims.JwtStore, jwtStore)
		}

		state, err = jwtStore.State(t.Claims.Jti)
		if err != nil {
			return state, err
		}

		if state != authpb.JWTState_VALID {
			return 0, errors.Forbidden
		}
	}
	return authpb.JWTState_VALID, nil
}

func (j *syncedVerifier) VerifyJWT(ctx context.Context, jwt string) (authpb.JWTState, error) {
	j.initStores()

	t, err := authpb.ParseJWT(jwt)
	if err != nil {
		return authpb.JWTState_NOT_VALID, err
	}

	return j.Verify(ctx, t)
}

func (j *syncedVerifier) saveJwtVerifier(name string, v authpb.TokenVerifier) {
	j.Lock()
	defer j.Unlock()
	j.tokenVerifiers[name] = v
}

func (j *syncedVerifier) getJwtVerifier(name string) authpb.TokenVerifier {
	j.Lock()
	defer j.Unlock()
	return j.tokenVerifiers[name]
}

func (j *syncedVerifier) getStore(name string) *SyncedStore {
	j.Lock()
	defer j.Unlock()
	return j.syncedStores[name]
}

func (j *syncedVerifier) saveStore(name string, s *SyncedStore) {
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
	infos, err := j.registry.GetOfType(pb2.Type_TokenStore)
	if err != nil {
		log.Error("[jwt verifier] could not load token stores info", log.Err(err))
		return
	}

	for _, info := range infos {
		for _, node := range info.Nodes {
			if node.Protocol == pb2.Protocol_Grpc {
				storeName := fmt.Sprintf("%s@%s", node.Id, info.Id)

				dictStore, err := dict.New(app.SQLiteConfig(filepath.Join(j.cacheDir, fmt.Sprintf("%s-jwt-store.db", node.Id))), "jwt", codec.Default)
				if err != nil {
					log.Error("[jwt verifier] failed to initialize store database", log.Err(err), log.Field("service", info.Id), log.Field("node", node.Id))
					return
				}

				CAPool := x509.NewCertPool()
				CAPool.AddCert(j.CaCert)
				tlsConfig := &tls.Config{
					RootCAs: CAPool,
					Certificates: []tls.Certificate{{
						Certificate: [][]byte{j.serviceCert.Raw},
						PrivateKey:  j.serviceKey,
					}},
				}

				jwtStore := NewSyncedStore(node.Address, tlsConfig, dictStore)
				j.syncedStores[storeName] = jwtStore
			}
		}
	}

	<-time.After(time.Second)
}

func NewSyncedVerifier(caCert, cert *x509.Certificate, privateKey crypto.PrivateKey, registry pb2.Registry, cacheDir string) authpb.TokenVerifier {
	verifier := &syncedVerifier{
		tokenVerifiers: map[string]authpb.TokenVerifier{},
		syncedStores:   map[string]*SyncedStore{},
		registry:       registry,
		cacheDir:       cacheDir,
		serviceKey:     privateKey,
		serviceCert:    cert,
		CaCert:         caCert,
	}
	return verifier
}
