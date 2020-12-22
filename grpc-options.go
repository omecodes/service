package service

import (
	"crypto/tls"
	ome "github.com/omecodes/libome"
)

type nodeOptions struct {
	register     bool
	port         int
	tlsConfig    *tls.Config
	interceptors []ome.GrpcContextUpdater
	md           MD
}

type NodeOption func(options *nodeOptions)

func WithPort(port int) NodeOption {
	return func(options *nodeOptions) {
		options.port = port
	}
}

func WithTLS(t *tls.Config) NodeOption {
	return func(options *nodeOptions) {
		options.tlsConfig = t
	}
}

func WithInterceptor(interceptors ...ome.GrpcContextUpdater) NodeOption {
	return func(options *nodeOptions) {
		options.interceptors = append(options.interceptors, interceptors...)
	}
}

func WithMeta(m MD) NodeOption {
	return func(options *nodeOptions) {
		options.md = m
	}
}

func Register(register bool) NodeOption {
	return func(options *nodeOptions) {
		options.register = register
	}
}
