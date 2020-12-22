package service

import (
	"context"
	"crypto"
	"crypto/x509"
	"github.com/omecodes/discover"
	"sync"

	"github.com/omecodes/libome"
	"google.golang.org/grpc/credentials"
)

type Box struct {
	params *Params

	serverMutex sync.Mutex

	gRPCNodes map[string]*gPRCNode
	httpNodes map[string]*httpNode

	registry                   ome.Registry
	caCert                     *x509.Certificate
	caClientAuthentication     credentials.PerRPCCredentials
	caGRPCTransportCredentials credentials.TransportCredentials
	registryCert               *x509.Certificate
	cert                       *x509.Certificate
	privateKey                 crypto.PrivateKey
	credentials                *ome.ProxyCredentials
	ctx                        context.Context
	ctxCancelFunc              context.CancelFunc

	info *ome.ServiceInfo

	dialerMutex sync.Mutex
	dialerCache map[string]Dialer
}

func CreateBox(ctx context.Context, p *Params, opts ...InitOption) (*Box, error) {
	b := &Box{params: p}
	err := b.validateParams()
	if err != nil {
		return nil, err
	}

	b.Dir()

	b.dialerCache = map[string]Dialer{}
	b.httpNodes = map[string]*httpNode{}
	b.gRPCNodes = map[string]*gPRCNode{}
	b.ctx = ContextWithBox(ctx, b)
	return b, b.Init(opts...)
}

func (box *Box) Context() context.Context {
	if box.ctx == nil {
		box.ctx = ContextWithBox(context.Background(), box)
	}
	return box.ctx
}

func (box *Box) Name() string {
	return box.params.Name
}

func (box *Box) Domain() string {
	return box.params.Domain
}

func (box *Box) AcmeEnabled() bool {
	return box.params.Acme
}

func (box *Box) IP() string {
	return box.params.Ip
}

func (box *Box) Dir() string {
	return box.params.Dir
}

func (box *Box) RegistryCert() *x509.Certificate {
	return box.registryCert
}

func (box *Box) Registry() ome.Registry {
	if box.registry == nil {
		box.registry = discover.NewZebouClient(box.params.RegistryAddress, box.ClientMutualTLS())
	}
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

func (box *Box) CertificateFilename() string {
	return box.params.CertificatePath
}

func (box *Box) KeyFilename() string {
	return box.params.KeyPath
}

// Stop stops all started services and gateways
func (box *Box) Stop() {
	_ = box.stopNodes()
	_ = box.stopGateways()
	if box.registry != nil {
		_ = box.registry.Stop()
	}
}
