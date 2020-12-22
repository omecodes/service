package service

import "crypto/tls"

type nodeOptions struct {
	forceRegister bool
	port          int
	tlsConfig     *tls.Config
	interceptors  []Interceptor
	md            MD
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

func WithInterceptor(interceptors ...Interceptor) NodeOption {
	return func(options *nodeOptions) {
		options.interceptors = append(options.interceptors, interceptors...)
	}
}

func WithMeta(m MD) NodeOption {
	return func(options *nodeOptions) {
		options.md = m
	}
}

func ForceRegister(register bool) NodeOption {
	return func(options *nodeOptions) {
		options.forceRegister = register
	}
}
