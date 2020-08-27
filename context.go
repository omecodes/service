package service

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"github.com/omecodes/common/errors"
	ome "github.com/omecodes/libome"
	pb "github.com/omecodes/libome/proto/service"
	"google.golang.org/grpc"
	"strings"
)

type box struct{}

type ctxServiceCredentials struct{}

type serviceContext struct{}

func serviceBox(ctx context.Context) *Box {
	val := ctx.Value(box{})
	if val == nil {
		srvCtx := ctx.Value(serviceContext{})
		if srvCtx == nil {
			return nil
		}
		val = srvCtx.(context.Context).Value(box{})
		if val == nil {
			return nil
		}
		return val.(*Box)
	}
	return val.(*Box)
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
	return box.privateKey
}

func Registry(ctx context.Context) pb.Registry {
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

	parts := strings.Split(box.params.CACredentials, ":")

	return &ome.ProxyCredentials{
		Key:    parts[0],
		Secret: parts[1],
	}
}

func Name(ctx context.Context) string {
	box := serviceBox(ctx)
	if box == nil {
		return ""
	}
	return box.params.Name
}

func Dir(ctx context.Context) string {
	box := serviceBox(ctx)
	if box == nil {
		return ""
	}
	return box.params.Dir
}

func ID(ctx context.Context) string {
	box := serviceBox(ctx)
	if box == nil {
		return ""
	}
	return box.params.Name
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

func Dial(ctx context.Context, st pb.Type) (*grpc.ClientConn, error) {
	box := serviceBox(ctx)
	if box == nil {
		return nil, errors.New("no service box associated to context")
	}
	return box.dialToService(st)
}

func ContextWithBox(ctx context.Context, b *Box) context.Context {
	return context.WithValue(ctx, box{}, b)
}

func BoxFromContext(ctx context.Context) *Box {
	return serviceBox(ctx)
}
