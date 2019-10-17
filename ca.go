package service

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	crypto2 "github.com/zoenion/common/crypto"
	pb "github.com/zoenion/service/proto"
	"net"
	"time"
)

type csrServerHandler struct {
	PrivateKey  crypto.PrivateKey
	Certificate *x509.Certificate
}

func (C *csrServerHandler) SignCertificate(ctx context.Context, in *pb.SignCertificateRequest) (*pb.SignCertificateResponse, error) {
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
		SignerCertificate: C.Certificate,
		SignerPrivateKey:  C.PrivateKey,
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
