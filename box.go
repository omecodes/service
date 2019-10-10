package service

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/iancoleman/strcase"
	crypto2 "github.com/zoenion/common/crypto"
	"github.com/zoenion/common/errors"
	"github.com/zoenion/common/futils"
	capb "github.com/zoenion/common/proto/ca"
	"github.com/zoenion/service/authentication"
	"github.com/zoenion/service/discovery"
	"github.com/zoenion/service/server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Box struct {
	params Params

	serverMutex sync.Mutex
	services    map[string]*grpc.Server
	gateways    map[string]*http.Server

	registry                   discovery.Registry
	caCert                     *x509.Certificate
	caClientAuthentication     credentials.PerRPCCredentials
	caGRPCTransportCredentials credentials.TransportCredentials
	registryCert               *x509.Certificate
	cert                       *x509.Certificate
	privateKey                 crypto.PrivateKey
}

func NewBox(p Params) (*Box, error) {
	b := &Box{params: p}
	err := b.validateParams()
	if err != nil {
		return nil, err
	}
	return b, b.Load()
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
	var err error
	box.params.Dir, err = filepath.Abs(box.params.Dir)
	if err != nil {
		log.Printf("command line: could not find %s\n", box.Dir())
		return err
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

func (box *Box) Load() error {
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

func (box *Box) listen(web bool, secure bool, port int, tc *tls.Config) (net.Listener, error) {
	var (
		listener net.Listener
		err      error
		address  string
	)

	if port > 0 {
		address = fmt.Sprintf("%s:%d", box.Ip(), port)
	} else {
		address = fmt.Sprintf("%s:", box.Ip())
	}

	if secure {
		err = box.loadSignedKeyPair()
		if err != nil {
			return nil, err
		}

		if tc == nil {
			if web {
				tc = box.serverWebTLS()
			} else {
				tc = box.serverMutualTLS()
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

func (box *Box) StartGatewayGRPCMapping(name string, g *server.GatewayServiceMapping) error {
	if box.registry == nil {
		box.serverMutex.Lock()
		defer box.serverMutex.Unlock()

		info, err := box.registry.Get(box.params.Namespace + ":" + name)
		if err != nil {
			return err
		}

		listener, err := box.listen(true, g.SecureConnection, g.Port, g.Tls)
		if err != nil {
			return err
		}

		address := listener.Addr().String()
		grpcServerEndpoint := flag.String("grpc-server-endpoint", info.ServiceNode.Address, "gRPC server endpoint")
		ctx := context.Background()
		mux := runtime.NewServeMux()
		opts := []grpc.DialOption{grpc.WithInsecure()}

		err = g.Binder(ctx, mux, *grpcServerEndpoint, opts)
		if err != nil {
			return err
		}

		log.Printf("starting %s.HTTP at %s", name, address)
		srv := &http.Server{
			Addr:    address,
			Handler: mux,
		}
		box.gateways[name] = srv
		go srv.Serve(listener)
		return nil
	}
	return errors.New("not found")
}

func (box *Box) StartGateway(name string, g *server.Gateway) error {
	box.serverMutex.Lock()
	defer box.serverMutex.Unlock()

	listener, err := box.listen(true, g.SecureConnection, g.Port, g.Tls)
	if err != nil {
		return err
	}

	address := listener.Addr().String()
	router := g.ProvideRouter()

	log.Printf("starting %s.HTTP at %s", name, address)
	srv := &http.Server{
		Addr:    address,
		Handler: router,
	}
	box.gateways[name] = srv
	go srv.Serve(listener)
	return nil
}

func (box *Box) StartService(name string, g *server.Service) error {
	box.serverMutex.Lock()
	defer box.serverMutex.Unlock()

	listener, err := box.listen(true, g.SecureConnection, g.Port, g.Tls)
	if err != nil {
		return err
	}
	address := listener.Addr().String()

	log.Printf("starting %s.gRPC at %s", name, address)
	var opts []grpc.ServerOption
	if g.Interceptor != nil {
		opts = append(opts, grpc.StreamInterceptor(g.Interceptor.InterceptStream), grpc.UnaryInterceptor(g.Interceptor.InterceptUnary))
	}

	srv := grpc.NewServer(opts...)
	box.services[name] = srv

	g.RegisterHandlerFunc(srv)
	go srv.Serve(nil)
	return nil
}

func (box *Box) StopServices() error {
	return nil
}

func (box *Box) StopService(name string) error {
	return nil
}

func (box *Box) StopGateway(name string) error {
	return nil
}

func (box *Box) StopGateways() error {
	return nil
}
