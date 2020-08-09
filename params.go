package service

import (
	"errors"
	"fmt"
	"github.com/omecodes/common/futils"
	"path/filepath"
)

type Params struct {
	Name            string
	Dir             string
	Domain          string
	Ip              string
	ExternalIp      string
	Acme            bool
	CertificatePath string
	KeyPath         string
	Autonomous      bool
	Keys            [][]byte

	WithRegistryServer bool
	RegistryAddress    string
	RegistrySecure     bool
	RegistryID         string
	StartRegistry      bool

	CA            bool
	CAAddress     string
	CACertPath    string
	CACredentials string
}

func (box *Box) validateParams() error {
	if box.params.Name == "" {
		return errors.New("command line: --name flags is required")
	}

	if box.params.Autonomous {
		return nil
	}

	if box.params.Domain == "" && box.params.Ip == "" {
		return errors.New("command line: one or both --domain and --ip flags must be passed")
	}

	var err error
	box.params.Dir, err = filepath.Abs(box.params.Dir)
	if err != nil {
		// log.Printf("command line: could not find %s\n", box.Dir())
		return err
	}

	if box.params.CAAddress == "" && !box.params.CA {
		return errors.New("command line: ca-addr flag must be passed")
	}

	if box.params.RegistryAddress == "" {
		return errors.New("command line: ca-addr flag must be passed")
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
		return fmt.Errorf("command line: ca-cred flag required")
	}

	/* if box.params.RegistryAddress != "" {
		if box.params.RegistryAddress != "" {
			return errors.New("command line: --namespace must always be provided with --registryAddress")
		}
	}*/

	if box.params.CertificatePath != "" || box.params.KeyPath != "" {
		if box.params.CertificatePath == "" || box.params.KeyPath == "" {
			return errors.New("command line: --cert must always be provided with --key")
		}
	}

	return nil
}
