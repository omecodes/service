package service

import (
	"github.com/zoenion/common/conf"
	"github.com/zoenion/service/discovery"
)

type Options struct {
	afterStart []func() error
	afterStop  []func()
}

type Option func(*Options)

func WithAfterStart(f func() error) Option {
	return func(opts *Options) {
		opts.afterStart = append(opts.afterStart, f)
	}
}

func WithAfterStop(f func()) Option {
	return func(opts *Options) {
		opts.afterStop = append(opts.afterStop, f)
	}
}

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

func WithRegistryServerDBConf(cfg conf.Map) InitOption {
	return func(options *initOptions) {
		options.RegistryServerDBConf = cfg
	}
}
