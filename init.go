package service

import (
	"crypto/tls"
	"fmt"
	"github.com/zoenion/common/conf"
	crypto2 "github.com/zoenion/common/crypto"
	"github.com/zoenion/common/database"
	"github.com/zoenion/common/errors"
	"github.com/zoenion/service/authentication"
	"github.com/zoenion/service/discovery"
	"github.com/zoenion/service/discovery/registry"
	"google.golang.org/grpc/credentials"
	"path/filepath"
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
		if options.RegistryServerDBConf == nil {
			options.RegistryServerDBConf = database.SQLiteConfig(filepath.Join(box.params.Dir, "registry.db"))
		}

		err = box.initRegistry(options.RegistryServerDBConf)
		if err != nil {
			return errors.Errorf("could not initialize registry: %s", err)
		}
	}

	if box.params.CA {
		return box.startCA(options.caProxyCredentials)
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
	box.caClientAuthentication = authentication.NewGRPCProxy(parts[0], parts[1])

	return
}

func (box *Box) initRegistry(dbCfg conf.Map) (err error) {
	var registryHost string
	if box.params.RegistryAddress == "" {
		registryHost = box.Host()
		box.params.RegistryAddress = fmt.Sprintf("%s%s", box.Host(), RegistryDefaultHost)

	} else {
		parts := strings.Split(box.params.RegistryAddress, ":")
		if len(parts) != 2 {
			return errors.New("malformed registry address. Should be like HOST:PORT")
		}
		registryHost = parts[0]
	}

	cfg := &registry.Configs{
		Name:        "registry",
		BindAddress: box.Host(),
		Certificate: box.ServiceCert(),
		PrivateKey:  box.ServiceKey(),
		Domain:      box.params.Domain,
		Generator:   discovery.IDGeneratorFunc(FullName),
		DB:          dbCfg,
	}

	if box.params.StartRegistry {

	}

	var syncedRegistry *registry.Server = nil
	if box.params.StartRegistry {
		syncedRegistry, err = registry.NewServer(cfg)
		if err == nil {
			err = syncedRegistry.Start()
		}

		if err != nil {
			syncedRegistry = nil
			err = nil
		}
	}

	if syncedRegistry == nil || registryHost != "" && registryHost != RegistryDefaultHost && registryHost != box.Host() {
		var tc *tls.Config
		tc = box.ClientMutualTLS()
		box.registry = registry.NewSyncedRegistryClient(box.params.RegistryAddress, tc, discovery.IDGeneratorFunc(FullName))
	} else {
		box.registry = syncedRegistry.Client()
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
