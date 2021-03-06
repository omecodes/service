package service

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"github.com/omecodes/common/errors"
	"github.com/omecodes/libome"
	"google.golang.org/grpc"
)

type ctxBox struct{}

type ctxServiceCredentials struct{}

func serviceBox(ctx context.Context) *Box {
	o := ctx.Value(ctxBox{})
	if o == nil {
		return nil
	}
	return o.(*Box)
}

func GetCACertificate(ctx context.Context) *x509.Certificate {
	box := serviceBox(ctx)
	if box == nil {
		return nil
	}
	return box.caCert
}

func GetCertificate(ctx context.Context) *x509.Certificate {
	box := serviceBox(ctx)
	if box == nil {
		return nil
	}
	return box.cert
}

func GetPrivateKey(ctx context.Context) crypto.PrivateKey {
	box := serviceBox(ctx)
	if box == nil {
		return nil
	}
	return box.key
}

func GetRegistry(ctx context.Context) ome.Registry {
	box := serviceBox(ctx)
	if box == nil {
		return nil
	}
	return box.registry
}

func CACredentials(ctx context.Context) *ome.ProxyCredentials {
	box := serviceBox(ctx)
	if box == nil {
		return nil
	}

	return &ome.ProxyCredentials{
		Key:    box.Options.caAPIKey,
		Secret: box.Options.caAPISecret,
	}
}

// Secret returns the application shared secret
func GetSecret(ctx context.Context) string {
	box := serviceBox(ctx)
	if box == nil {
		return ""
	}
	return box.caAPISecret
}

func GetName(ctx context.Context) string {
	box := serviceBox(ctx)
	if box == nil {
		return ""
	}
	return box.Options.name
}

func GetDir(ctx context.Context) string {
	box := serviceBox(ctx)
	if box == nil {
		return ""
	}
	return box.Options.workingDir
}

func GetID(ctx context.Context) string {
	box := serviceBox(ctx)
	if box == nil {
		return ""
	}
	return box.Options.name
}

func GetGatewayAddress(ctx context.Context, name string) string {
	box := serviceBox(ctx)
	if box == nil {
		return ""
	}
	gt, ok := box.httpNodes[name]
	if !ok {
		return ""
	}
	return gt.URL()
}

func GetClientTLSConfig(ctx context.Context) (*tls.Config, error) {
	box := serviceBox(ctx)
	if box == nil {
		return nil, errors.NotSupported
	}
	return box.ClientMutualTLS()
}

func Dial(ctx context.Context, st uint32) (*grpc.ClientConn, error) {
	box := serviceBox(ctx)
	if box == nil {
		return nil, errors.New("no service box associated to context")
	}
	return box.dialToService(st)
}

func ContextWithBox(ctx context.Context, b *Box) context.Context {
	return context.WithValue(ctx, ctxBox{}, b)
}

func BoxFromContext(ctx context.Context) *Box {
	return serviceBox(ctx)
}
