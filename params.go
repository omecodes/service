package service

import (
	"errors"
	"path/filepath"
	"strings"

	"github.com/omecodes/common/futils"
	"github.com/omecodes/libome"
)

type TLSInfo struct {
	CertificatePath string
	KeyPath         string
}

type NetworkInfo struct {
	Domain       string
	Ip           string
	OtherDomains []string
	ExternalIp   string
}

type CAInfo struct {
	CAAddress     string
	CACertPath    string
	CACredentials string
}

type Params struct {
	NetworkInfo
	TLSInfo
	CAInfo

	Name            string
	Dir             string
	RegistryAddress string
}

func (box *Box) validateParams() error {
	if box.params.Name == "" {
		return errors.New("box params: name is empty")
	}

	if box.params.Domain == "" && box.params.Ip == "" {
		return errors.New("box params: both domain and ip are empty")
	}

	var err error
	box.params.Dir, err = filepath.Abs(box.params.Dir)
	if err != nil {
		return err
	}

	if box.params.CAAddress == "" {
		return errors.New("box params: CA address is empty")
	}

	if box.params.CACertPath == "" {
		var err error
		caCertPath, err := filepath.Abs("./ca.crt")
		if caCertPath == "" || err != nil || !futils.FileExists(caCertPath) {
			caCertPath = filepath.Join(box.params.Dir, "certs", "ca.crt")
		}
		box.params.CACertPath = caCertPath
	}

	if box.params.CACredentials == "" {
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
