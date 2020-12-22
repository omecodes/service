package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/iancoleman/strcase"
	"github.com/omecodes/common/errors"
	"github.com/omecodes/common/futils"
	"github.com/omecodes/common/utils/log"
	"github.com/omecodes/libome"
	"github.com/omecodes/libome/crypt"
	"google.golang.org/grpc"
)

func (box *Box) loadOrGenerateCertificateKeyPair() (err error) {
	if box.cert != nil && box.privateKey != nil {
		return
	}

	if box.params.CACertPath == "" {
		err = errors.New("missing CA certificate path")
		return
	}

	box.params.CACertPath, _ = filepath.Abs(box.params.CACertPath)
	if !futils.FileExists(box.params.CACertPath) {
		err = errors.New("could not find CA certificate")
		return
	}

	box.caCert, err = crypt.LoadCertificate(box.params.CACertPath)
	if err != nil {
		return errors.Errorf("could not load CA certificate: %s", err)
	}

	name := strcase.ToSnake(box.params.Name)
	if box.params.CertificatePath == "" {
		box.params.CertificatePath = filepath.Join(box.params.Dir, fmt.Sprintf("%s.crt", name))
	}

	if box.params.KeyPath == "" {
		box.params.KeyPath = filepath.Join(box.params.Dir, fmt.Sprintf("%s.key", name))
	}

	shouldGenerateNewPair := !futils.FileExists(box.params.CertificatePath) || !futils.FileExists(box.params.KeyPath)
	if !shouldGenerateNewPair {
		box.privateKey, err = crypt.LoadPrivateKey([]byte{}, box.params.KeyPath)
		if err != nil {
			return fmt.Errorf("could not load private key: %s", err)
		}

		box.cert, err = crypt.LoadCertificate(box.params.CertificatePath)
		if err != nil {
			return fmt.Errorf("could not load certificate: %s", err)
		}
	}

	CAPool := x509.NewCertPool()
	CAPool.AddCert(box.caCert)
	if box.cert != nil {
		_, err = box.cert.Verify(x509.VerifyOptions{Roots: CAPool})
		if err != nil || time.Now().After(box.cert.NotAfter) || time.Now().Before(box.cert.NotBefore) {
			if err != nil {
				log.Error("service certificate verification failed", log.Err(err))
			}
			shouldGenerateNewPair = true
		}
	}

	if shouldGenerateNewPair {
		box.privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("could not generate key pair: %s", err)
		}
		pub := box.privateKey.(*ecdsa.PrivateKey).PublicKey

		if box.caClientAuthentication == nil {
			parts := strings.Split(box.params.CACredentials, ":")
			box.caClientAuthentication = ome.NewGRPCBasic(parts[0], parts[1])
		}

		conn, err := grpc.Dial(box.params.CAAddress, grpc.WithTransportCredentials(box.caGRPCTransportCredentials), grpc.WithPerRPCCredentials(box.caClientAuthentication))
		if err != nil {
			return err
		}

		client := ome.NewCSRClient(conn)
		csrData := &ome.CSRData{
			Domains:   []string{box.params.Domain},
			Addresses: box.IpList(),
			Subject:   strcase.ToDelimited(box.params.Name, '.'),
			PublicKey: elliptic.Marshal(elliptic.P256(), pub.X, pub.Y),
		}

		rsp, err := client.SignCertificate(context.Background(), &ome.SignCertificateRequest{
			Csr: csrData,
		})
		if err != nil {
			return fmt.Errorf("could not sign certificate: %s", err)
		}

		box.cert, err = x509.ParseCertificate(rsp.RawCertificate)
		if err != nil {
			return err
		}

		_ = crypt.StoreCertificate(box.cert, box.params.CertificatePath, os.ModePerm)
		_ = crypt.StorePrivateKey(box.privateKey, nil, box.params.KeyPath)
	}
	return nil
}

func (box *Box) serverMutualTLS() *tls.Config {
	if box.privateKey == nil || box.cert == nil || box.caCert == nil {
		return nil
	}
	CAPool := x509.NewCertPool()
	CAPool.AddCert(box.caCert)
	tlsCert := tls.Certificate{
		Certificate: [][]byte{box.cert.Raw},
		PrivateKey:  box.privateKey,
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		ClientCAs:    CAPool,
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ServerName:   box.params.Domain,
	}
}

func (box *Box) ServerTLS() *tls.Config {
	if box.privateKey == nil || box.cert == nil || box.caCert == nil {
		return nil
	}
	tlsCert := tls.Certificate{
		Certificate: [][]byte{box.cert.Raw},
		PrivateKey:  box.privateKey,
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		ServerName:   box.params.Domain,
	}
}

func (box *Box) ClientMutualTLS() *tls.Config {
	if box.privateKey == nil || box.cert == nil || box.caCert == nil {
		return nil
	}
	CAPool := x509.NewCertPool()
	CAPool.AddCert(box.caCert)

	tlsCert := tls.Certificate{
		Certificate: [][]byte{box.cert.Raw},
		PrivateKey:  box.privateKey.(*ecdsa.PrivateKey),
	}
	return &tls.Config{
		RootCAs:      CAPool,
		Certificates: []tls.Certificate{tlsCert},
	}
}

func (box *Box) ClientTLS() *tls.Config {
	if box.caCert != nil {
		CAPool := x509.NewCertPool()
		CAPool.AddCert(box.caCert)
		return &tls.Config{
			RootCAs: CAPool,
		}
	}
	return nil
}
