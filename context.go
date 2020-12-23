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

func CACertificate(ctx context.Context) *x509.Certificate {
	box := serviceBox(ctx)
	if box == nil {
		return nil
	}
	return box.caCert
}

func Certificate(ctx context.Context) *x509.Certificate {
	box := serviceBox(ctx)
	if box == nil {
		return nil
	}
	return box.cert
}

func PrivateKey(ctx context.Context) crypto.PrivateKey {
	box := serviceBox(ctx)
	if box == nil {
		return nil
	}
	return box.key
}

func Registry(ctx context.Context) ome.Registry {
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
		Key:    box.options.caAPIKey,
		Secret: box.options.caAPISecret,
	}
}

// Secret returns the application shared secret
func Secret(ctx context.Context) string {
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
	return box.options.name
}

func GetDir(ctx context.Context) string {
	box := serviceBox(ctx)
	if box == nil {
		return ""
	}
	return box.options.workingDir
}

func ID(ctx context.Context) string {
	box := serviceBox(ctx)
	if box == nil {
		return ""
	}
	return box.options.name
}

func GatewayAddress(ctx context.Context, name string) string {
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

func ClientTLSConfig(ctx context.Context) *tls.Config {
	box := serviceBox(ctx)
	if box == nil {
		return nil
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
