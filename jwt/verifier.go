package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/zoenion/common"
	"github.com/zoenion/common/codec"
	crypto2 "github.com/zoenion/common/crypto"
	"github.com/zoenion/common/database"
	"github.com/zoenion/common/errors"
	"github.com/zoenion/common/log"
	"github.com/zoenion/common/persist/dict"
	authpb "github.com/zoenion/common/proto/auth"
	"github.com/zoenion/service/discovery"
	pb2 "github.com/zoenion/service/proto"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type RevokedHandlerFunc func()

type jwtVerifier struct {
	sync.Mutex
	registry          discovery.Registry
	storesMutex       sync.Mutex
	tokenVerifiers    map[string]authpb.TokenVerifier
	syncedStores      map[string]*SyncedStore
	CaCert            *x509.Certificate
	serviceCert       *x509.Certificate
	serviceKey        crypto.PrivateKey
	cacheDir          string
	storesInitialized bool
}

func (j *jwtVerifier) Verify(ctx context.Context, t *authpb.JWT) (authpb.JWTState, error) {

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

		encodedKey := s.Meta[common.MetaTokenVerifyingKey]
		key, _, err := crypto2.PEMDecodePublicKey([]byte(encodedKey))
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
				log.Error("[jwt verifier] failed to get node info", err, log.Field("service", serviceName), log.Field("node", nodeName))
				return 0, errors.Forbidden
			}

			dictStore, err := dict.NewSQL(database.SQLiteConfig(filepath.Join(j.cacheDir, "jwt-store.db")), "jwt", codec.Default)
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
	}
	return authpb.JWTState_VALID, nil
}

func (j *jwtVerifier) VerifyJWT(ctx context.Context, jwt string) (authpb.JWTState, error) {
	j.initStores()

	t, err := authpb.TokenFromJWT(jwt)
	if err != nil {
		return authpb.JWTState_NOT_VALID, err
	}

	return j.Verify(ctx, t)
}

func (j *jwtVerifier) saveJwtVerifier(name string, v authpb.TokenVerifier) {
	j.Lock()
	defer j.Unlock()
	j.tokenVerifiers[name] = v
}

func (j *jwtVerifier) getJwtVerifier(name string) authpb.TokenVerifier {
	j.Lock()
	defer j.Unlock()
	return j.tokenVerifiers[name]
}

func (j *jwtVerifier) getStore(name string) *SyncedStore {
	j.Lock()
	defer j.Unlock()
	return j.syncedStores[name]
}

func (j *jwtVerifier) saveStore(name string, s *SyncedStore) {
	j.Lock()
	defer j.Unlock()
	j.syncedStores[name] = s
}

func (j *jwtVerifier) initStores() {
	j.Lock()
	defer j.Unlock()

	if j.storesInitialized {
		return
	}
	j.storesInitialized = true

	log.Info("[jwt verifier] initializing token stores")
	infos, err := j.registry.GetOfType(pb2.Type_TokenStore)
	if err != nil {
		log.Error("[jwt verifier] could not load token stores info", err)
		return
	}

	for _, info := range infos {
		serviceID := discovery.GenerateID(info.Namespace, info.Name)
		for _, node := range info.Nodes {
			if node.Protocol == pb2.Protocol_Grpc {
				storeName := fmt.Sprintf("%s@%s", node.Name, serviceID)

				dictStore, err := dict.NewSQL(database.SQLiteConfig(filepath.Join(j.cacheDir, fmt.Sprintf("%s-jwt-store.db", node.Name))), "jwt", codec.Default)
				if err != nil {
					log.Error("[jwt verifier] failed to initialize store database", err, log.Field("service", serviceID), log.Field("node", node.Name))
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

	<- time.After(time.Second)
}

func NewVerifier(caCert, cert *x509.Certificate, privateKey crypto.PrivateKey, registry discovery.Registry, cacheDir string) authpb.TokenVerifier {
	verifier := &jwtVerifier{
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
