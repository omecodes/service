package service

import (
	"fmt"
	"github.com/omecodes/libome/v2/ports"
	"strings"

	"github.com/omecodes/common/errors"
	"github.com/omecodes/common/utils/log"
	"github.com/omecodes/libome/v2"
	"github.com/omecodes/libome/v2/crypt"
	"github.com/omecodes/service/v2/registry"
	"google.golang.org/grpc/credentials"
)

// Init initializes box from parameters
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

	if !box.params.NoRegistry {
		box.registry = options.registry
		if options.registry == nil {
			err = box.initRegistry()
			if err != nil {
				return errors.Errorf("could not initialize registry: %s", err)
			}
		}
	}
	return nil
}

func (box *Box) loadCertificateKeyPairFromFiles() error {
	var err error
	box.cert, err = crypt.LoadCertificate(box.params.CertificatePath)
	if err == nil {
		box.privateKey, err = crypt.LoadPrivateKey(nil, box.params.KeyPath)
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

	box.caCert, err = crypt.LoadCertificate(box.params.CACertPath)
	if err != nil {
		return
	}

	box.caGRPCTransportCredentials, err = credentials.NewClientTLSFromFile(box.params.CACertPath, "")
	if err != nil {
		return
	}

	parts := strings.Split(box.params.CACredentials, ":")
	box.caClientAuthentication = ome.NewGRPCProxy(parts[0], parts[1])

	return
}

func (box *Box) initRegistry() (err error) {
	if box.params.RegistryAddress == "" {
		box.params.RegistryAddress = fmt.Sprintf("%s:%d", box.Host(), ports.Discover)

	} else {
		parts := strings.Split(box.params.RegistryAddress, ":")
		if len(parts) != 2 {
			if len(parts) == 1 {
				box.params.RegistryAddress = fmt.Sprintf("%s:%d", box.params.RegistryAddress, ports.Discover)
			}
			return errors.New("malformed registry address. Should be like HOST:PORT")
		}
	}

	if box.params.RegistryServer {
		dc := &registry.ServerConfig{
			BindAddress:  box.params.RegistryAddress,
			CertFilename: box.CertificateFilename(),
			KeyFilename:  box.KeyFilename(),
			StoreDir:     box.Dir(),
		}
		box.registry, err = registry.Serve(dc)
		if err != nil {
			log.Error("impossible to run discovery server", log.Err(err))
		}
	} else {
		box.registry = registry.NewZebouClient(box.params.RegistryAddress, box.ClientTLS())
	}
	return
}

// Stop stops all started services and gateways
func (box *Box) Stop() {
	_ = box.stopServices()
	_ = box.stopGateways()
	if box.registry != nil {
		_ = box.registry.Stop()
	}
}
