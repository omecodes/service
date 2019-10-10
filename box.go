package service

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/iancoleman/strcase"
	"github.com/zoenion/common"
	crypto2 "github.com/zoenion/common/crypto"
	"github.com/zoenion/common/errors"
	"github.com/zoenion/common/futils"
	"github.com/zoenion/common/prompt"
	capb "github.com/zoenion/common/proto/ca"
	"github.com/zoenion/service/authentication"
	"github.com/zoenion/service/cmd"
	"github.com/zoenion/service/discovery"
	"github.com/zoenion/service/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type BoxConfigsLoader interface {
	Load(ctx context.Context) (*Configs, error)
}

type Box struct {
	params cmd.Params

	servers                    *servers
	registry                   discovery.Registry
	caCert                     *x509.Certificate
	caClientAuthentication     credentials.PerRPCCredentials
	caGRPCTransportCredentials credentials.TransportCredentials
	registryCert               *x509.Certificate
	cert                       *x509.Certificate
	privateKey                 crypto.PrivateKey
}

func (box *Box) Name() string {
	return box.params.Name
}

func (box *Box) Dir() string {
	return box.params.Dir
}

func (box *Box) Ip() string {
	return box.params.Ip
}

func (box *Box) RegistryCert() *x509.Certificate {
	return box.registryCert
}

func (box *Box) Registry() discovery.Registry {
	return box.registry
}

func (box *Box) AuthorityCert() *x509.Certificate {
	return box.caCert
}

func (box *Box) AuthorityClientAuthentication() credentials.PerRPCCredentials {
	return box.caClientAuthentication
}

func (box *Box) AuthorityGRPCTransportCredentials() credentials.TransportCredentials {
	return box.caGRPCTransportCredentials
}

func (box *Box) ServiceCert() *x509.Certificate {
	return box.cert
}

func (box *Box) ServiceKey() crypto.PrivateKey {
	return box.privateKey
}

func (box *Box) GRPCAddress() string {
	addr := box.params.Domain
	if addr == "" {
		addr = box.params.Ip
	}
	return fmt.Sprintf("%s:%s", addr, box.params.GatewayGRPCPort)
}

func (box *Box) HTTPAddress() string {
	addr := box.params.Domain
	if addr == "" {
		addr = box.params.Ip
	}
	return fmt.Sprintf("%s:%s", addr, box.params.GatewayHTTPPort)
}

func (box *Box) validateParams() error {
	if box.params.Name == "" {
		return errors.New("command line: --name flags is required")
	}

	if box.params.Domain == "" && box.params.Ip == "" {
		return errors.New("command line: one or both --domain and --ip flags must be passed")
	}

	if box.params.Dir == "" {
		d := getDir()
		box.params.Dir = d.Path()
		if err := d.Create(); err != nil {
			log.Printf("command line: could not create %s. Might not be writeable\n", box.Dir())
			return err
		}
	} else {
		var err error
		box.params.Dir, err = filepath.Abs(box.params.Dir)
		if err != nil {
			log.Printf("command line: could not find %s\n", box.Dir())
			return err
		}
	}

	if box.params.CaGRPC != "" || box.params.CaCertPath != "" || box.params.CaCredentials != "" {
		if box.params.CaGRPC == "" || box.params.CaCertPath == "" || box.params.CaCredentials == "" {
			return fmt.Errorf("command line: --a-grpc must always be provided with --a-cert and --a-cred")
		}
	}

	if box.params.RegistryAddress != "" || box.params.Namespace != "" {
		if box.params.RegistryAddress != "" && box.params.Namespace == "" {
			return errors.New("command line: --namespace must always be provided with --registryAddress")
		}
	}

	if box.params.CertificatePath != "" || box.params.KeyPath != "" {
		if box.params.CertificatePath == "" || box.params.KeyPath == "" {
			return errors.New("command line: --cert must always be provided with --key")
		}
	}

	return nil
}

func (box *Box) loadTools() error {
	var err error

	if box.params.CertificatePath != "" {
		box.cert, err = crypto2.LoadCertificate(box.params.CaCertPath)
		if err != nil {
			return fmt.Errorf("could not load service certificate: %s", err)
		}

		box.privateKey, err = crypto2.LoadPrivateKey(nil, box.params.KeyPath)
		if err != nil {
			return fmt.Errorf("could not load service private key: %s", err)
		}
	}

	if box.params.CaGRPC != "" {
		box.caCert, err = crypto2.LoadCertificate(box.params.CaCertPath)
		if err != nil {
			return fmt.Errorf("could not load authority certificate: %s", err)
		}

		box.caGRPCTransportCredentials, err = credentials.NewClientTLSFromFile(box.params.CaCertPath, "")
		if err != nil {
			return fmt.Errorf("could not create authority client credentials: %s", box.params.CaCertPath)
		}

		parts := strings.Split(box.params.CaCredentials, ":")
		box.caClientAuthentication = authentication.NewGRPCBasic(parts[0], parts[1])

		err = box.loadSignedKeyPair()
		if err != nil {
			return err
		}
	}

	if box.params.RegistryAddress != "" {
		if box.params.RegistrySecure {
			box.registry = NewSyncRegistry(box.params.RegistryAddress, box.clientMutualTLS())
		} else {
			box.registry = NewSyncRegistry(box.params.RegistryAddress, nil)
		}
	}
	return nil
}

func (box *Box) loadSignedKeyPair() error {
	if box.cert != nil && box.privateKey != nil {
		return nil
	}

	if box.params.CaCertPath == "" {
		return errors.BadInput
	}

	box.params.CaCertPath, _ = filepath.Abs(box.params.CaCertPath)
	if !futils.FileExists(box.params.CaCertPath) {
		return errors.NotFound
	}
	authorityCert, err := crypto2.LoadCertificate(box.params.CaCertPath)
	if err != nil {
		return fmt.Errorf("could not load authority certificate: %s", err)
	}

	box.caCert = authorityCert

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
	CAPool.AddCert(authorityCert)

	if box.cert != nil {
		_, err = box.cert.Verify(x509.VerifyOptions{Roots: CAPool})
		if err != nil || time.Now().After(box.cert.NotAfter) || time.Now().Before(box.cert.NotBefore) {
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
			parts := strings.Split(box.params.CaCredentials, ":")
			box.caClientAuthentication = authentication.NewGRPCBasic(parts[0], parts[1])
		}

		conn, err := grpc.Dial(box.params.CaGRPC, grpc.WithTransportCredentials(box.caGRPCTransportCredentials), grpc.WithPerRPCCredentials(box.caClientAuthentication))
		client := capb.NewAuthorityServiceClient(conn)
		rsp, err := client.SignCertificate(context.Background(), &capb.SignCertificateRequest{
			Template: &capb.CertificateTemplate{
				Domains:     []string{box.params.Domain},
				Addresses:   []string{box.params.Ip},
				ServiceName: strcase.ToDelimited(box.params.Name, '.'),
				PublicKey:   elliptic.Marshal(elliptic.P256(), pub.X, pub.Y),
			},
		})
		if err != nil {
			return fmt.Errorf("could not sign certificate: %s", err)
		}

		box.cert, err = x509.ParseCertificate(rsp.RawCertificate)
		if err != nil {
			return err
		}

		_ = crypto2.StoreCertificate(box.cert, certFilename, os.ModePerm)
		_ = crypto2.StorePrivateKey(box.privateKey, nil, keyFilename)
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

func (box *Box) serverWebTLS() *tls.Config {
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

func (box *Box) clientMutualTLS() *tls.Config {
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

func (box *Box) gatewayToGrpcClientTls() *tls.Config {
	if box.caCert != nil {
		CAPool := x509.NewCertPool()
		CAPool.AddCert(box.caCert)
		return &tls.Config{
			RootCAs: CAPool,
		}
	}
	return nil
}

func (box *Box) start(cfg *Configs) error {

	if cfg.HTTP != nil {
		if cfg.HTTP.Tls == nil {
			cfg.HTTP.Tls = box.serverMutualTLS()
			/*if cfg.HTTP.ClientGRPCTls == nil {
				cfg.HTTP.ClientGRPCTls = box.gatewayToGrpcClientTls()
			}*/
		}
	}

	if cfg.GRPC != nil {
		if cfg.GRPC.Tls == nil {
			cfg.GRPC.Tls = box.serverWebTLS()
		}
	}

	box.servers = &servers{
		name:        box.params.Name,
		gRPC:        cfg.GRPC,
		web:         cfg.HTTP,
		gRPCAddress: box.GRPCAddress(),
		httpAddress: box.HTTPAddress(),
	}

	return box.servers.start()
}

func (box *Box) stop() {
	if box.servers != nil {
		box.servers.stop()
	}
}

func Run(loader BoxConfigsLoader, params cmd.Params) {
	box := new(Box)
	if params.Name == "" {
		params.Name = AppName
	}

	if params.Dir == "" {
		d := getDir()
		err := d.Create()
		if err != nil {
			log.Fatalf("could not initialize configs dir: %s\n", err)
		}
		params.Dir = d.path
	}

	box.params = params
	if err := box.validateParams(); err != nil {
		log.Fatalln(err)
	}

	if err := box.loadTools(); err != nil {
		log.Fatalln(err)
	}

	ctx := context.WithValue(context.Background(), ctxBox, box)
	cfg, err := loader.Load(ctx)
	if err != nil {
		log.Fatalf("could not load box configs: %s\n", err)
	}

	if err := box.start(cfg); err != nil {
		log.Fatalf("starting %s service: %s\n", box.Name, err)
	}

	if box.registry != nil {

		meta := map[string]string{}

		certEncoded, _ := crypto2.PEMEncodeCertificate(box.cert)
		if certEncoded != nil {
			meta[common.ServiceCertificate] = string(certEncoded)
		}

		for k, m := range cfg.Meta {
			meta[k] = m
		}

		box.params.RegistryID, err = box.registry.Register(&proto.Info{
			Type:      cfg.Type,
			Name:      strcase.ToDelimited(box.Name(), '-'),
			Namespace: box.params.Namespace,
			Label:     strcase.ToCamel(box.params.Name),
			Nodes:     box.servers.nodes(),
			Meta:      meta,
		})
		if err != nil {
			log.Printf("could not register service: %s\n", err)
		}
	}
	opts := Options{}
	for _, opt := range cfg.Options {
		opt(&opts)
	}

	for _, sc := range opts.afterStart {
		if err = sc(); err != nil {
			log.Fatalln("got error while executing start callback:", err)
		}
	}

	<-prompt.QuitSignal()

	box.stop()
	if box.params.RegistryID != "" {
		err = box.registry.Deregister(box.params.RegistryID)
		if err != nil {
			log.Printf("could not de-register service: %s\n", err)
		}
	}

	for _, sc := range opts.afterStop {
		sc()
	}
}
