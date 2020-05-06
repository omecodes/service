package service

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	crypto2 "github.com/zoenion/common/crypto"
	"github.com/zoenion/common/errors"
	"github.com/zoenion/common/grpc-authentication"
	pb "github.com/zoenion/service/proto"
	"net"
	"time"
)

type csrServerHandler struct {
	credentials *ga.ProxyCredentials
	PrivateKey  crypto.PrivateKey
	Certificate *x509.Certificate
}

func (h *csrServerHandler) SignCertificate(ctx context.Context, in *pb.SignCertificateRequest) (*pb.SignCertificateResponse, error) {
	if h.credentials != nil {
		proxyCredentials := ga.ProxyCredentialsFromContext(ctx)
		if proxyCredentials == nil || proxyCredentials.Key != h.credentials.Key || proxyCredentials.Secret != h.credentials.Secret {
			return nil, errors.Forbidden
		}
	}

	var ips []net.IP
	for _, a := range in.Csr.Addresses {
		ips = append(ips, net.ParseIP(a))
	}

	x, y := elliptic.Unmarshal(elliptic.P256(), in.Csr.PublicKey)
	k := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	cert, err := crypto2.GenerateServiceCertificate(&crypto2.CertificateTemplate{
		Name:              in.Csr.Subject,
		SignerCertificate: h.Certificate,
		SignerPrivateKey:  h.PrivateKey,
		PublicKey:         k,
		Domains:           in.Csr.Domains,
		IPs:               ips,
		Expiry:            time.Hour * 24 * 730,
	})
	if err != nil {
		return nil, err
	}

	return &pb.SignCertificateResponse{
		RawCertificate: cert.Raw,
	}, nil
}
