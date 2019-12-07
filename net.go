package service

import (
	"crypto/tls"
	"fmt"
	"github.com/zoenion/service/errors"
	pb "github.com/zoenion/service/proto"
	"net"
)

func (box *Box) listen(port int, security pb.Security, tc *tls.Config) (net.Listener, error) {
	var (
		listener net.Listener
		err      error
		address  string
	)

	if port > 0 {
		address = fmt.Sprintf("%s:%d", box.Host(), port)
	} else {
		address = fmt.Sprintf("%s:", box.Host())
	}

	if !box.params.Autonomous && (tc != nil || security != pb.Security_None) {
		if tc == nil {
			err = box.loadOrGenerateCertificateKeyPair()
			if err != nil {
				return nil, err
			}

			if security == pb.Security_TLS {
				tc = box.serverTLS()
			} else if security == pb.Security_MutualTLS {
				tc = box.serverMutualTLS()
			} else {
				return nil, errors.New("unsupported security type")
			}
		}
		listener, err = tls.Listen("tcp", address, tc)
		if err != nil {
			return nil, err
		}

	} else {
		listener, err = net.Listen("tcp", address)
		if err != nil {
			return nil, err
		}
	}
	return listener, err
}

func (box *Box) Host() string {
	if box.params.Domain != "" {
		return box.params.Domain
	}

	if box.params.ExternalIp != "" {
		return box.params.ExternalIp
	}

	return box.params.Ip
}

func (box *Box) BindIP() string {
	return box.params.Ip
}

func (box *Box) ExternalIP() string {
	return box.params.ExternalIp
}

func (box *Box) IpList() []string {
	l := []string{box.params.Ip}
	if box.params.ExternalIp != "" && box.params.ExternalIp != box.params.Ip {
		l = append(l, box.params.ExternalIp)
	}
	return l
}
