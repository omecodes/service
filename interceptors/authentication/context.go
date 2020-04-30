package authentication

import (
	"context"
)

type proxyCredentials struct{}
type credentials struct{}
type jwt struct{}

func ContextWithJWT(ctx context.Context, j string) context.Context {
	return context.WithValue(ctx, jwt{}, j)
}

func ContextWithCredentials(ctx context.Context, c *Credentials) context.Context {
	return context.WithValue(ctx, credentials{}, c)
}

func ContextWithProxyCredentials(ctx context.Context, credentials2 *ProxyCredentials) context.Context {
	return context.WithValue(ctx, proxyCredentials{}, credentials2)
}

func CredentialsFromContext(ctx context.Context) *Credentials {
	o := ctx.Value(credentials{})
	if c, ok := o.(*Credentials); ok {
		return c
	}
	return nil
}

func ProxyCredentialsFromContext(ctx context.Context) *ProxyCredentials {
	o := ctx.Value(proxyCredentials{})
	if c, ok := o.(*ProxyCredentials); ok {
		return c
	}
	return nil
}

func JWTFromContext(ctx context.Context) string {
	o := ctx.Value(jwt{})
	if c, ok := o.(string); ok {
		return c
	}
	return ""
}
