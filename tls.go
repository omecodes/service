package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/iancoleman/strcase"
	crypto2 "github.com/zoenion/common/crypto"
	"github.com/zoenion/common/errors"
	"github.com/zoenion/common/futils"
	"github.com/zoenion/service/authentication"
	pb "github.com/zoenion/service/proto"
	"google.golang.org/grpc"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (box *Box) loadOrGenerateCACertificateKeyPair() (err error) {
	if box.cert != nil && box.privateKey != nil {
		return nil
	}

	name := strcase.ToSnake(box.params.Name)
	certFilename := filepath.Join(box.params.Dir, fmt.Sprintf("%s.crt", name))
	keyFilename := filepath.Join(box.params.Dir, fmt.Sprintf("%s.key", name))

	shouldGenerateNewPair := !futils.FileExists(certFilename) || !futils.FileExists(keyFilename)
	if !shouldGenerateNewPair {
		box.privateKey, err = crypto2.LoadPrivateKey([]byte{}, keyFilename)
		if err != nil {
			return fmt.Errorf("could not load private key: %s", err)
		}

		box.cert, err = crypto2.LoadCertificate(certFilename)
		if err != nil {
			return fmt.Errorf("could not load certificate: %s", err)
		}
		return
	}

	if shouldGenerateNewPair {
		box.privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("could not generate key pair: %s", err)
		}
		pub := box.privateKey.(*ecdsa.PrivateKey).PublicKey

		caCertTemplate := &crypto2.CertificateTemplate{
			Organization:      "oe",
			Name:              "CA-" + box.params.Name,
			Domains:           []string{box.params.Domain},
			IPs:               []net.IP{net.ParseIP(box.params.Ip)},
			Expiry:            time.Hour * 24 * 370,
			PublicKey:         &pub,
			SignerPrivateKey:  box.privateKey,
			SignerCertificate: box.cert,
		}
		if box.params.ExternalIp != "" {
			caCertTemplate.IPs = append(caCertTemplate.IPs, net.ParseIP(box.params.ExternalIp))
		}

		box.cert, err = crypto2.GenerateCACertificate(caCertTemplate)
		if err != nil {
			return fmt.Errorf("could not generate CA cert: %s", err)
		}

		_ = crypto2.StoreCertificate(box.cert, certFilename, os.ModePerm)
		_ = crypto2.StorePrivateKey(box.privateKey, nil, keyFilename)
	}
	return
}

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

	box.caCert, err = crypto2.LoadCertificate(box.params.CACertPath)
	if err != nil {
		return errors.Errorf("could not load CA certificate: %s", err)
	}

	name := strcase.ToSnake(box.params.Name)
	certFilename := filepath.Join(box.params.Dir, fmt.Sprintf("%s.crt", name))
	keyFilename := filepath.Join(box.params.Dir, fmt.Sprintf("%s.key", name))

	shouldGenerateNewPair := !futils.FileExists(certFilename) || !futils.FileExists(keyFilename)
	if !shouldGenerateNewPair {
		box.privateKey, err = crypto2.LoadPrivateKey([]byte{}, keyFilename)
		if err != nil {
			return fmt.Errorf("could not load private key: %s", err)
		}

		box.cert, err = crypto2.LoadCertificate(certFilename)
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
				log.Println("service certificate verification failed:", err)
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
			box.caClientAuthentication = authentication.NewGRPCBasic(parts[0], parts[1])
		}

		conn, err := grpc.Dial(box.params.CAAddress, grpc.WithTransportCredentials(box.caGRPCTransportCredentials), grpc.WithPerRPCCredentials(box.caClientAuthentication))
		if err != nil {
			return err
		}

		client := pb.NewCSRClient(conn)
		csrData := &pb.CSRData{
			Domains:   []string{box.params.Domain},
			Addresses: box.IpList(),
			Subject:   strcase.ToDelimited(box.params.Name, '.'),
			PublicKey: elliptic.Marshal(elliptic.P256(), pub.X, pub.Y),
		}

		rsp, err := client.SignCertificate(context.Background(), &pb.SignCertificateRequest{
			Csr: csrData,
		})
		if err != nil {
			return fmt.Errorf("could not sign certificate: %s", err)
		}

		box.cert, err = x509.ParseCertificate([]byte(rsp.RawCertificate))
		if err != nil {
			return err
		}

		_ = crypto2.StoreCertificate(box.cert, certFilename, os.ModePerm)
		_ = crypto2.StorePrivateKey(box.privateKey, nil, keyFilename)
	}
	return nil
}

func (box *Box) serverMutualTLS() *tls.Config {
	if box.privateKey == nil || box.cert == nil || box.caCert == nil && !box.params.CA {
		return nil
	}
	CAPool := x509.NewCertPool()
	if box.params.CA {
		CAPool.AddCert(box.cert)
	} else {
		CAPool.AddCert(box.caCert)
	}
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

func (box *Box) serverTLS() *tls.Config {
	if box.privateKey == nil || box.cert == nil || box.caCert == nil && !box.params.CA {
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

func (box *Box) clientMutualTLS() *tls.Config {
	if box.privateKey == nil || box.cert == nil || box.caCert == nil && !box.params.CA {
		return nil
	}
	CAPool := x509.NewCertPool()
	if box.params.CA {
		CAPool.AddCert(box.cert)
	} else {
		CAPool.AddCert(box.caCert)
	}
	tlsCert := tls.Certificate{
		Certificate: [][]byte{box.cert.Raw},
		PrivateKey:  box.privateKey.(*ecdsa.PrivateKey),
	}
	return &tls.Config{
		RootCAs:      CAPool,
		Certificates: []tls.Certificate{tlsCert},
	}
}

func (box *Box) gatewayToGRPCClientTls() *tls.Config {
	if box.caCert != nil {
		CAPool := x509.NewCertPool()
		CAPool.AddCert(box.caCert)
		return &tls.Config{
			RootCAs: CAPool,
		}
	}
	return nil
}
