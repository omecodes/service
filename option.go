package service

import (
	"github.com/zoenion/common/conf"
	"github.com/zoenion/service/discovery"
)

type initOptions struct {
	registry             discovery.Registry
	credentialsProvider  func(...string) string
	RegistryServerDBConf conf.Map
}

type InitOption func(*initOptions)

func WithCACredentialsProvider(cp func(...string) string) InitOption {
	return func(opts *initOptions) {
		opts.credentialsProvider = cp
	}
}
