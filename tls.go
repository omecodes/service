package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"google.golang.org/grpc/credentials"
	"os"
	"path/filepath"
	"time"

	"github.com/iancoleman/strcase"
	"github.com/omecodes/common/errors"
	"github.com/omecodes/common/futils"
	"github.com/omecodes/common/utils/log"
	"github.com/omecodes/libome"
	"github.com/omecodes/libome/crypt"
	"google.golang.org/grpc"
)

func (opts *Options) loadCertificateKeyPairFromFiles() error {
	var err error
	opts.cert, err = crypt.LoadCertificate(opts.certificateFilename)
	if err == nil {
		opts.key, err = crypt.LoadPrivateKey(nil, opts.certificateFilename)
	}
	return err
}

func (opts *Options) loadOrGenerateCertificateKeyPair() (err error) {
	if opts.cert != nil && opts.key != nil {
		return
	}

	if opts.caCertFilename == "" {
		err = errors.New("missing CA certificate path")
		return
	}

	opts.caCertFilename, _ = filepath.Abs(opts.caCertFilename)
	if !futils.FileExists(opts.caCertFilename) {
		err = errors.New("could not find CA certificate")
		return
	}

	opts.caCert, err = crypt.LoadCertificate(opts.caCertFilename)
	if err != nil {
		return errors.Errorf("could not load CA certificate: %s", err)
	}

	name := strcase.ToSnake(opts.name)
	if opts.certificateFilename == "" {
		opts.certificateFilename = filepath.Join(opts.workingDir, fmt.Sprintf("%s.crt", name))
	}

	if opts.keyFilename == "" {
		opts.keyFilename = filepath.Join(opts.workingDir, fmt.Sprintf("%s.key", name))
	}

	shouldGenerateNewPair := !futils.FileExists(opts.certificateFilename) || !futils.FileExists(opts.keyFilename)
	if !shouldGenerateNewPair {
		opts.key, err = crypt.LoadPrivateKey([]byte{}, opts.keyFilename)
		if err != nil {
			return fmt.Errorf("could not load private key: %s", err)
		}

		opts.cert, err = crypt.LoadCertificate(opts.certificateFilename)
		if err != nil {
			return fmt.Errorf("could not load certificate: %s", err)
		}
	}

	CAPool := x509.NewCertPool()
	CAPool.AddCert(opts.caCert)
	if opts.cert != nil {
		_, err = opts.cert.Verify(x509.VerifyOptions{Roots: CAPool})
		if err != nil || time.Now().After(opts.cert.NotAfter) || time.Now().Before(opts.cert.NotBefore) {
			if err != nil {
				log.Error("service certificate verification failed", log.Err(err))
			}
			shouldGenerateNewPair = true
		}
	}

	if shouldGenerateNewPair {
		opts.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("could not generate key pair: %s", err)
		}
		pub := opts.key.(*ecdsa.PrivateKey).PublicKey

		gAuth := ome.NewGRPCBasic(opts.caAPIKey, opts.caAPISecret)
		transportCredentials, err := credentials.NewClientTLSFromFile(opts.caCertFilename, "")
		if err != nil {
			return err
		}

		conn, err := grpc.Dial(opts.caAddr, grpc.WithTransportCredentials(transportCredentials), grpc.WithPerRPCCredentials(gAuth))
		if err != nil {
			return err
		}

		client := ome.NewCSRClient(conn)
		csrData := &ome.CSRData{
			Domains:   []string{opts.netMainDomain},
			Addresses: opts.IpList(),
			Subject:   strcase.ToDelimited(opts.name, '.'),
			PublicKey: elliptic.Marshal(elliptic.P256(), pub.X, pub.Y),
		}

		rsp, err := client.SignCertificate(context.Background(), &ome.SignCertificateRequest{
			Csr: csrData,
		})
		if err != nil {
			return fmt.Errorf("could not sign certificate: %s", err)
		}

		opts.cert, err = x509.ParseCertificate(rsp.RawCertificate)
		if err != nil {
			return err
		}

		_ = crypt.StoreCertificate(opts.cert, opts.certificateFilename, os.ModePerm)
		_ = crypt.StorePrivateKey(opts.key, nil, opts.keyFilename)
	}
	return
}

func (opts *Options) serverMutualTLS() *tls.Config {
	if opts.key == nil || opts.cert == nil || opts.caCert == nil {
		return nil
	}
	CAPool := x509.NewCertPool()
	CAPool.AddCert(opts.caCert)
	tlsCert := tls.Certificate{
		Certificate: [][]byte{opts.cert.Raw},
		PrivateKey:  opts.key,
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		ClientCAs:    CAPool,
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ServerName:   opts.netMainDomain,
	}
}

func (opts *Options) ServerTLS() *tls.Config {
	if opts.key == nil || opts.cert == nil || opts.caCert == nil {
		return nil
	}
	tlsCert := tls.Certificate{
		Certificate: [][]byte{opts.cert.Raw},
		PrivateKey:  opts.key,
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		ServerName:   opts.netMainDomain,
	}
}

func (opts *Options) ClientMutualTLS() *tls.Config {
	if opts.key == nil || opts.cert == nil || opts.caCert == nil {
		return nil
	}
	CAPool := x509.NewCertPool()
	CAPool.AddCert(opts.caCert)

	tlsCert := tls.Certificate{
		Certificate: [][]byte{opts.cert.Raw},
		PrivateKey:  opts.key.(*ecdsa.PrivateKey),
	}
	return &tls.Config{
		RootCAs:      CAPool,
		Certificates: []tls.Certificate{tlsCert},
	}
}

func (opts *Options) ClientTLS() *tls.Config {
	if opts.caCert != nil {
		CAPool := x509.NewCertPool()
		CAPool.AddCert(opts.caCert)
		return &tls.Config{
			RootCAs: CAPool,
		}
	}
	return nil
}
