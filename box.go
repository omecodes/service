package service

import (
	"context"
	"crypto"
	"crypto/x509"
	pb "github.com/omecodes/common/proto/service"
	"google.golang.org/grpc/credentials"
	"sync"
)

type Box struct {
	params Params

	serverMutex sync.Mutex

	gRPCNodes map[string]*gPRCNode
	httpNodes map[string]*httpNode

	registry                   pb.Registry
	caCert                     *x509.Certificate
	caClientAuthentication     credentials.PerRPCCredentials
	caGRPCTransportCredentials credentials.TransportCredentials
	registryCert               *x509.Certificate
	cert                       *x509.Certificate
	privateKey                 crypto.PrivateKey

	ctx           context.Context
	ctxCancelFunc context.CancelFunc

	info *pb.Info

	dialerMutex sync.Mutex
	dialerCache map[string]Dialer
}

func NewBox(p Params) (*Box, error) {
	b := &Box{params: p}
	err := b.validateParams()
	if err != nil {
		return nil, err
	}

	b.dialerCache = map[string]Dialer{}
	b.httpNodes = map[string]*httpNode{}
	b.gRPCNodes = map[string]*gPRCNode{}
	b.ctx, b.ctxCancelFunc = context.WithCancel(context.WithValue(context.Background(), box{}, b))
	return b, nil
}

func NewBoxWithContext(ctx context.Context, p Params) (*Box, error) {
	b := &Box{params: p}
	err := b.validateParams()
	if err != nil {
		return nil, err
	}

	b.dialerCache = map[string]Dialer{}
	b.httpNodes = map[string]*httpNode{}
	b.gRPCNodes = map[string]*gPRCNode{}
	b.ctx, b.ctxCancelFunc = context.WithCancel(context.WithValue(ctx, box{}, b))
	return b, nil
}

func (box *Box) Context() context.Context {
	return box.ctx
}

func (box *Box) Name() string {
	return box.params.Name
}

func (box *Box) Domain() string {
	return box.params.Domain
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

func (box *Box) Registry() pb.Registry {
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
