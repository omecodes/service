package service

import (
	"github.com/omecodes/common/utils/log"
	"github.com/omecodes/discover"
	err2 "github.com/omecodes/libome/errors"
)

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
	opts.registry, err = discover.Serve(dc)
	if err != nil {
		log.Error("impossible to run discovery server", log.Err(err))
	}

	return nil
}

func (opts *Options) StopRegistry() error {
	if opts.registry == nil {
		return nil
	}

	if stopper, ok := opts.registry.(interface {
		Stop() error
	}); ok {
		return stopper.Stop()
	}
	return nil
}
