package service

import (
	"fmt"
	crypto2 "github.com/omecodes/common/crypto"
	"github.com/omecodes/common/errors"
	"github.com/omecodes/common/grpc-authentication"
	"github.com/omecodes/common/log"
	"github.com/omecodes/discover"
	"google.golang.org/grpc/credentials"
	"strings"
)

func (box *Box) Init(opts ...InitOption) error {
	if box.params.Autonomous {
		return nil
	}

	var err error
	options := &initOptions{}
	for _, opt := range opts {
		opt(options)
	}

	if box.params.CertificatePath != "" {
		err = box.loadCertificateKeyPairFromFiles()
		if err != nil {
			return errors.Errorf("could not load certificate/key pair from file: %s", err)
		}
	} else {
		if box.params.CA {
			err = box.loadOrGenerateCACertificateKeyPair()
			if err != nil {
				return errors.Errorf("could not load CA key pair: %s", err)
			}

		} else {
			err = box.loadCACredentials()
			if err != nil {
				return errors.Errorf("could not initialize CA credentials: %s", err)
			}

			err = box.loadOrGenerateCertificateKeyPair()
			if err != nil {
				return err
			}
		}
	}

	box.registry = options.registry
	if options.registry == nil {
		err = box.initRegistry()
		if err != nil {
			return errors.Errorf("could not initialize registry: %s", err)
		}
	}

	return nil
}

func (box *Box) loadCertificateKeyPairFromFiles() error {
	var err error
	box.cert, err = crypto2.LoadCertificate(box.params.CertificatePath)
	if err == nil {
		box.privateKey, err = crypto2.LoadPrivateKey(nil, box.params.KeyPath)
	}
	return err
}

func (box *Box) loadCACredentials() (err error) {
	if box.params.CACertPath == "" {
		return errors.New("missing CA certificate path parameter")
	}

	if box.params.CACredentials == "" {
		return errors.New("missing CA client login/password parameter")
	}

	box.caCert, err = crypto2.LoadCertificate(box.params.CACertPath)
	if err != nil {
		return
	}

	box.caGRPCTransportCredentials, err = credentials.NewClientTLSFromFile(box.params.CACertPath, "")
	if err != nil {
		return
	}

	parts := strings.Split(box.params.CACredentials, ":")
	box.caClientAuthentication = ga.NewGRPCProxy(parts[0], parts[1])

	return
}

func (box *Box) initRegistry() (err error) {
	if box.params.RegistryAddress == "" {
		box.params.RegistryAddress = fmt.Sprintf("%s%s", box.Host(), RegistryDefaultHost)

	} else {
		parts := strings.Split(box.params.RegistryAddress, ":")
		if len(parts) != 2 {
			if len(parts) == 1 {
				box.params.RegistryAddress = box.params.RegistryAddress + RegistryDefaultHost
			}
			return errors.New("malformed registry address. Should be like HOST:PORT")
		}
	}

	if box.params.WithRegistryServer {
		dc := &discover.ServerConfig{
			BindAddress:  box.params.RegistryAddress,
			CertFilename: box.CertificateFilename(),
			KeyFilename:  box.KeyFilename(),
		}
		box.registry, err = discover.Serve(dc)
		if err != nil {
			log.Error("impossible to run discovery server", err)
		}
	} else {
		box.registry = discover.NewMSGClient(box.params.RegistryAddress, box.ClientTLS())
	}
	return
}

func (box *Box) Stop() {
	_ = box.stopServices()
	_ = box.stopGateways()
	if box.registry != nil {
		_ = box.registry.Stop()
	}
}
