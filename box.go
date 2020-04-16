package service

import (
	"context"
	"crypto"
	"crypto/x509"
	"github.com/zoenion/service/connection"
	"github.com/zoenion/service/discovery"
	"github.com/zoenion/service/server"
	"google.golang.org/grpc/credentials"
	"sync"
)

type Box struct {
	params Params
	boxDir string

	serverMutex sync.Mutex

	services map[string]*server.Service
	gateways map[string]*server.Gateway

	registry                   discovery.Registry
	caCert                     *x509.Certificate
	caClientAuthentication     credentials.PerRPCCredentials
	caGRPCTransportCredentials credentials.TransportCredentials
	registryCert               *x509.Certificate
	cert                       *x509.Certificate
	privateKey                 crypto.PrivateKey

	ctx           context.Context
	ctxCancelFunc context.CancelFunc

	dialerMutex sync.Mutex
	dialerCache map[string]connection.Dialer
}

func NewBox(p Params) (*Box, error) {
	b := &Box{params: p}
	err := b.validateParams()
	if err != nil {
		return nil, err
	}

	b.dialerCache = map[string]connection.Dialer{}
	b.gateways = map[string]*server.Gateway{}
	b.services = map[string]*server.Service{}
	b.ctx, b.ctxCancelFunc = context.WithCancel(context.WithValue(context.Background(), box{}, b))
	return b, nil
}

func NewBoxWithContext(ctx context.Context, p Params) (*Box, error) {
	b := &Box{params: p}
	err := b.validateParams()
	if err != nil {
		return nil, err
	}

	b.dialerCache = map[string]connection.Dialer{}
	b.gateways = map[string]*server.Gateway{}
	b.services = map[string]*server.Service{}
	b.ctx, b.ctxCancelFunc = context.WithCancel(context.WithValue(ctx, box{}, b))
	return b, nil
}

func (box *Box) Context() context.Context {
	return box.ctx
}

func (box *Box) Name() string {
	return box.params.Name
}

func (box *Box) FullName() string {
	return FullName(box.params.Namespace, box.params.Name)
}

func (box *Box) Dir() string {
	return box.params.Dir
}

func (box *Box) RegistryCert() *x509.Certificate {
	return box.registryCert
}

func (box *Box) Registry() discovery.Registry {
	return box.registry
}

func (box *Box) CACertificate() *x509.Certificate {
	return box.caCert
}

func (box *Box) ServiceCert() *x509.Certificate {
	return box.cert
}

func (box *Box) ServiceKey() crypto.PrivateKey {
	return box.privateKey
}
