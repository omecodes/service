package service

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"github.com/omecodes/common/errors"
	"github.com/omecodes/common/grpcx"
	"github.com/omecodes/common/ome/crypt"
	pb "github.com/omecodes/common/ome/proto/service"
	"net"
	"time"
)

type csrServerHandler struct {
	credentialsVerifyFunc grpcx.ProxyCredentialsVerifyFunc
	PrivateKey            crypto.PrivateKey
	Certificate           *x509.Certificate
}

func (h *csrServerHandler) SignCertificate(ctx context.Context, in *pb.SignCertificateRequest) (*pb.SignCertificateResponse, error) {
	cred := grpcx.ProxyCredentialsFromContext(ctx)
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

	return &pb.SignCertificateResponse{
		RawCertificate: cert.Raw,
	}, nil
}
