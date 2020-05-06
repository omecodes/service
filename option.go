package service

import (
	"github.com/zoenion/common/conf"
	"github.com/zoenion/common/grpc-authentication"
	"github.com/zoenion/service/discovery"
)

type initOptions struct {
	registry             discovery.Registry
	RegistryServerDBConf conf.Map
	caProxyCredentials   *ga.ProxyCredentials
}

type InitOption func(*initOptions)

func WithCACredentials(pc *ga.ProxyCredentials) InitOption {
	return func(opts *initOptions) {
		opts.caProxyCredentials = pc
	}
}
