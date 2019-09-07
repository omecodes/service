package authentication

import (
	"context"
	"encoding/base64"
	"fmt"
)

type gRPCClientApiAccess struct {
	key, secret string
}

func (g *gRPCClientApiAccess) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": fmt.Sprintf("Access %s:%s", g.key, g.secret),
	}, nil
}

func (g *gRPCClientApiAccess) RequireTransportSecurity() bool {
	return true
}

func NewGRPCClientApiAccess(key, secret string) *gRPCClientApiAccess {
	return &gRPCClientApiAccess{
		key:    key,
		secret: secret,
	}
}

type gRPCClientBasic struct {
	user, password string
}

func (g *gRPCClientBasic) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	authentication := fmt.Sprintf("%s:%s", g.user, g.password)
	authentication = base64.StdEncoding.EncodeToString([]byte(authentication))
	return map[string]string{
		"authorization": fmt.Sprintf("Basic %s", authentication),
	}, nil
}

func (g *gRPCClientBasic) RequireTransportSecurity() bool {
	return true
}

func NewGRPCBasic(user, password string) *gRPCClientBasic {
	return &gRPCClientBasic{
		user:     user,
		password: password,
	}
}

type gRPCClientJwt struct {
	jwt string
}

func (g *gRPCClientJwt) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": "Bearer " + g.jwt,
	}, nil
}

func (g *gRPCClientJwt) RequireTransportSecurity() bool {
	return true
}

func NewGRPCClientJwt(t string) *gRPCClientJwt {
	return &gRPCClientJwt{jwt: t}
}
