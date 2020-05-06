package service

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/zoenion/common/errors"
	"github.com/zoenion/common/grpc-authentication"
	"github.com/zoenion/service/discovery"
	pb "github.com/zoenion/service/proto"
	"google.golang.org/grpc"
	"strings"
)

type box struct{}
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

func Registry(ctx context.Context) discovery.Registry {
	box := serviceBox(ctx)
	if box == nil {
		return nil
	}
	return box.registry
}

func Namespace(ctx context.Context) string {
	box := serviceBox(ctx)
	if box == nil {
		return ""
	}
	return box.params.Namespace
}

func ProxyCredentials(ctx context.Context) *ga.ProxyCredentials {
	box := serviceBox(ctx)
	if box == nil {
		return nil
	}

	parts := strings.Split(box.params.CACredentials, ":")

	return &ga.ProxyCredentials{
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
	return fmt.Sprintf("%s:%s", box.params.Namespace, box.params.Name)
}

func GatewayAddress(ctx context.Context, name string) string {
	box := serviceBox(ctx)
	if box == nil {
		return ""
	}
	gt, ok := box.gateways[name]
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

func Dial(ctx context.Context, st pb.Type, selectors ...pb.Selector) (*grpc.ClientConn, error) {
	box := serviceBox(ctx)
	if box == nil {
		return nil, errors.New("no service box associated to context")
	}
	return box.dialToService(st, selectors...)
}

func ContextWithBox(ctx context.Context, b *Box) context.Context {
	return context.WithValue(ctx, box{}, b)
}
