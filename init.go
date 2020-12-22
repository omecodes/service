package service

import (
	"strings"

	"github.com/omecodes/common/errors"
	"github.com/omecodes/libome"
	"github.com/omecodes/libome/crypt"
	"google.golang.org/grpc/credentials"
)

// Init initializes box from parameters
func (box *Box) Init(opts ...InitOption) error {
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
		err = box.loadCACredentials()
		if err != nil {
			return errors.Errorf("could not initialize CA credentials: %s", err)
		}

		err = box.loadOrGenerateCertificateKeyPair()
		if err != nil {
			return err
		}
	}

	if options.registry != nil {
		box.registry = options.registry
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
