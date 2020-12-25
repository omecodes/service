package service

import (
	"github.com/omecodes/discover"
	ome "github.com/omecodes/libome"
	err2 "github.com/omecodes/libome/errors"
	"github.com/omecodes/libome/logs"
)

type wrappedRegistry struct {
	server discover.Server
}

func (r *wrappedRegistry) RegisterService(info *ome.ServiceInfo) error {
	return r.server.RegisterService(info)
}

func (r *wrappedRegistry) DeregisterService(id string, nodes ...string) error {
	return r.server.DeregisterService(id, nodes...)
}

func (r *wrappedRegistry) GetService(id string) (*ome.ServiceInfo, error) {
	return r.server.GetService(id)
}

func (r *wrappedRegistry) GetNode(id string, nodeId string) (*ome.Node, error) {
	return r.server.GetNode(id, nodeId)
}

func (r *wrappedRegistry) Certificate(id string) ([]byte, error) {
	return r.server.Certificate(id)
}

func (r *wrappedRegistry) ConnectionInfo(id string, protocol ome.Protocol) (*ome.ConnectionInfo, error) {
	return r.server.ConnectionInfo(id, protocol)
}

func (r *wrappedRegistry) RegisterEventHandler(h ome.EventHandler) string {
	return r.server.RegisterEventHandler(h)
}

func (r *wrappedRegistry) DeregisterEventHandler(s string) {
	r.server.DeregisterEventHandler(s)
}

func (r *wrappedRegistry) GetOfType(t uint32) ([]*ome.ServiceInfo, error) {
	return r.server.GetOfType(t)
}

func (r *wrappedRegistry) FirstOfType(t uint32) (*ome.ServiceInfo, error) {
	return r.server.FirstOfType(t)
}

func (r *wrappedRegistry) Stop() error {
	return r.server.Stop()
}

func (opts *Options) StartRegistryServer(opt ...Option) (err error) {
	opts.override(opt...)

	if opts.regAddr == "" {
		return err2.New(err2.CodeBadRequest, "missing registry address")
	}

	dc := &discover.ServerConfig{
		Name:                 opts.name,
		StoreDir:             opts.workingDir,
		BindAddress:          opts.regAddr,
		CertFilename:         opts.certificateFilename,
		KeyFilename:          opts.keyFilename,
		ClientCACertFilename: opts.caCertFilename,
	}

	server, err := discover.Serve(dc)
	if err != nil {
		logs.Error("impossible to run discovery server", logs.Err(err))
	}

	// strange behavior emerges when doing directly opts.registry = server
	opts.registry = &wrappedRegistry{server: server}

	return nil
}

func (opts *Options) StopRegistry() error {
	if opts.registry == nil {
		return nil
	}
	return opts.registry.Stop()
}
