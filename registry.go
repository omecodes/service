package service

import (
	"github.com/omecodes/discover"
	"github.com/omecodes/errors"
	"github.com/omecodes/libome/logs"
)

func (opts *Options) StartRegistryServer(opt ...Option) (err error) {
	opts.override(opt...)

	if opts.regAddr == "" {
		return errors.Create(errors.BadRequest, "missing registry address")
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

	opts.registry = server
	return nil
}

func (opts *Options) StopRegistry() error {
	if opts.registry == nil {
		return nil
	}
	return opts.registry.Stop()
}
