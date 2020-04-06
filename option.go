package service

import (
	"github.com/zoenion/common/conf"
	"github.com/zoenion/service/discovery"
	"github.com/zoenion/service/interceptors/authentication"
)

type initOptions struct {
	registry             discovery.Registry
	RegistryServerDBConf conf.Map
	caProxyCredentials   *authentication.ProxyCredentials
}

type InitOption func(*initOptions)

func WithCACredentials(pc *authentication.ProxyCredentials) InitOption {
	return func(opts *initOptions) {
		opts.caProxyCredentials = pc
	}
}
