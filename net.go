package service

import (
	"crypto/tls"
	"fmt"
	"net"

	"github.com/omecodes/common/errors"
	"github.com/omecodes/libome"
)

func (opts *Options) listen(port int, security ome.Security) (net.Listener, *tls.Config, error) {
	var (
		listener net.Listener
		err      error
		address  string
	)

	if port > 0 {
		address = fmt.Sprintf("%s:%d", opts.Host(), port)
	} else {
		address = fmt.Sprintf("%s:", opts.Host())
	}

	var tc *tls.Config
	if security != ome.Security_Insecure {
		err = opts.loadOrGenerateCertificateKeyPair()
		if err != nil {
			return nil, nil, err
		}

		if security == ome.Security_Tls {
			tc, err = opts.ServerTLS()
		} else if security == ome.Security_MutualTls {
			tc, err = opts.serverMutualTLS()
		} else {
			return nil, nil, errors.New("unsupported security type")
		}

		if err != nil {
			return nil, nil, err
		}

		listener, err = tls.Listen("tcp", address, tc)
		if err != nil {
			return nil, nil, err
		}

	} else {
		listener, err = net.Listen("tcp", address)
		if err != nil {
			return nil, nil, err
		}
	}
	return listener, tc, err
}
