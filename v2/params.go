package service

import (
	"errors"
	"path/filepath"
	"strings"

	"github.com/omecodes/common/futils"
	"github.com/omecodes/libome/v2"
)

type Params struct {
	Name            string
	Dir             string
	Domain          string
	OtherDomains    []string
	Ip              string
	ExternalIp      string
	Acme            bool
	CertificatePath string
	KeyPath         string
	Autonomous      bool
	Keys            [][]byte

	NoRegistry      bool
	RegistryServer  bool
	RegistryAddress string
	RegistrySecure  bool
	RegistryID      string

	CA            bool
	CAAddress     string
	CACertPath    string
	CACredentials string
}

func (box *Box) validateParams() error {
	if box.params.Name == "" {
		return errors.New("box params: name is empty")
	}

	if box.params.Autonomous {
		return nil
	}

	if box.params.Domain == "" && box.params.Ip == "" {
		return errors.New("box params: both domain and ip are empty")
	}

	var err error
	box.params.Dir, err = filepath.Abs(box.params.Dir)
	if err != nil {
		return err
	}

	if box.params.CAAddress == "" && !box.params.CA {
		return errors.New("box params: CA address is empty")
	}

	if !box.params.NoRegistry && box.params.RegistryAddress == "" {
		return errors.New("box params: registry server address is empty")
	}

	if box.params.CACertPath == "" {
		var err error
		caCertPath, err := filepath.Abs("./ca.crt")
		if caCertPath == "" || err != nil || !futils.FileExists(caCertPath) {
			caCertPath = filepath.Join(box.params.Dir, "certs", "ca.crt")
		}
		box.params.CACertPath = caCertPath
	}

	if !box.params.CA && box.params.CACredentials == "" {
		return errors.New("box params: CA credentials is empty")
	}

	if box.params.CACredentials != "" {
		parts := strings.Split(box.params.CACredentials, ":")
		box.credentials = new(ome.ProxyCredentials)
		box.credentials.Key = parts[0]
		if len(parts) > 1 {
			box.credentials.Secret = parts[1]
		}
	}

	if box.params.CertificatePath != "" || box.params.KeyPath != "" {
		if box.params.CertificatePath == "" || box.params.KeyPath == "" {
			return errors.New("box params: certificate and key file paths are empty")
		}
	}

	return nil
}
