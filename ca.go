package service

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"github.com/omecodes/common/errors"
	"github.com/omecodes/libome"
	"github.com/omecodes/libome/crypt"
	"net"
	"time"
)

type csrServerHandler struct {
	ome.UnimplementedCSRServer
	credentialsVerifyFunc CredentialsValidatorFunc
	PrivateKey            crypto.PrivateKey
	Certificate           *x509.Certificate
}

func (h *csrServerHandler) SignCertificate(ctx context.Context, in *ome.SignCertificateRequest) (*ome.SignCertificateResponse, error) {
	cred := ome.ProxyCredentialsFromContext(ctx)

	valid, err := h.credentialsVerifyFunc(cred)
	if err != nil {
		return nil, err
	}

	if !valid {
		return nil, errors.Unauthorized
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

	cert, err := crypt.GenerateServiceCertificate(&crypt.CertificateTemplate{
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

	return &ome.SignCertificateResponse{
		RawCertificate: cert.Raw,
	}, nil
}
