package service

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	context2 "github.com/zoenion/service/context"
	"github.com/zoenion/service/discovery"
)

type contextKey string

const (
	ctxBox = contextKey("box")
)

func CACertificate(ctx context.Context) *x509.Certificate {
	val := ctx.Value(ctxBox)
	if val == nil {
		return nil
	}
	return val.(*Box).caCert
}

func Certificate(ctx context.Context) *x509.Certificate {
	val := ctx.Value(ctxBox)
	if val == nil {
		return nil
	}
	return val.(*Box).cert
}

func PrivateKey(ctx context.Context) crypto.PrivateKey {
	val := ctx.Value(ctxBox)
	if val == nil {
		return nil
	}
	return val.(*Box).privateKey
}

func Registry(ctx context.Context) discovery.Registry {
	val := ctx.Value(ctxBox)
	if val == nil {
		return nil
	}
	return val.(*Box).registry
}

func Namespace(ctx context.Context) string {
	val := ctx.Value(ctxBox)
	if val == nil {
		return ""
	}
	return val.(*Box).params.Namespace
}

func Name(ctx context.Context) string {
	val := ctx.Value(ctxBox)
	if val == nil {
		return ""
	}
	return val.(*Box).params.Name
}

func Dir(ctx context.Context) string {
	val := ctx.Value(ctxBox)
	if val == nil {
		return ""
	}
	return val.(*Box).params.Dir
}

func WebAddress(ctx context.Context) string {
	val := ctx.Value(ctxBox)
	if val == nil {
		return ""
	}
	box := val.(*Box)
	if box.gateway.web.Tls != nil {
		return fmt.Sprintf("https://%s", box.gateway.httpAddress)
	} else {
		return fmt.Sprintf("http://%s", box.gateway.httpAddress)
	}
}

func FullName(ctx context.Context) string {
	val := ctx.Value(ctxBox)
	if val == nil {
		return ""
	}
	box := val.(*Box)
	return fmt.Sprintf("%s:%s", box.params.Namespace, box.params.Name)
}

func ClientTLSConfig(ctx context.Context) *tls.Config {
	val := ctx.Value(ctxBox)
	if val == nil {
		return nil
	}
	box := val.(*Box)
	return box.clientMutualTLS()
}

func RequestUser(ctx context.Context) (string, bool) {
	value := ctx.Value(context2.User)
	if user, ok := value.(string); ok {
		return user, true
	}
	return "", false
}

func RequestUserAgent(ctx context.Context) (string, bool) {
	value := ctx.Value(context2.UserAgent)
	if userAgent, ok := value.(string); ok {
		return userAgent, true
	}
	return "", false
}
