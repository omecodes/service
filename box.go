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
	"github.com/zoenion/service/authentication"
	"github.com/zoenion/service/discovery"
	"github.com/zoenion/service/interceptors"
	pb "github.com/zoenion/service/proto"
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
	boxDir string

	serverMutex sync.Mutex
	services    map[string]*runningService
	gateways    map[string]*http.Server

	registry                   *SyncedRegistry
	caCert                     *x509.Certificate
	caClientAuthentication     credentials.PerRPCCredentials
	caGRPCTransportCredentials credentials.TransportCredentials
	registryCert               *x509.Certificate
	cert                       *x509.Certificate
	privateKey                 crypto.PrivateKey

	ctx           context.Context
	ctxCancelFunc context.CancelFunc
}

func NewBox(p Params) (*Box, error) {
	b := &Box{params: p}
	err := b.validateParams()
	if err != nil {
		return nil, err
	}
	b.gateways = map[string]*http.Server{}
	b.services = map[string]*runningService{}
	b.ctx, b.ctxCancelFunc = context.WithCancel(context.WithValue(context.Background(), ctxBox, b))
	return b, nil
}

func (box *Box) loadKeyPair() error {
	if box.cert != nil && box.privateKey != nil {
		return nil
	}

	if !box.params.CA && box.params.CACertPath == "" {
		return errors.BadInput
	}

	if box.params.CACertPath != "" {
		box.params.CACertPath, _ = filepath.Abs(box.params.CACertPath)
		if !futils.FileExists(box.params.CACertPath) {
			return errors.NotFound
		}
		authorityCert, err := crypto2.LoadCertificate(box.params.CACertPath)
		if err != nil {
			return fmt.Errorf("could not load authority certificate: %s", err)
		}

		box.caCert = authorityCert
	}
	var err error

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

	if !box.params.CA {
		CAPool := x509.NewCertPool()
		CAPool.AddCert(box.caCert)
		if box.cert != nil {
			_, err = box.cert.Verify(x509.VerifyOptions{Roots: CAPool})
			if err != nil || time.Now().After(box.cert.NotAfter) || time.Now().Before(box.cert.NotBefore) {
				shouldGenerateNewPair = true
			}
		}
	}

	if shouldGenerateNewPair {
		box.privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("could not generate key pair: %s", err)
		}
		pub := box.privateKey.(*ecdsa.PrivateKey).PublicKey

		if box.params.CA {
			box.cert, err = crypto2.GenerateCACertificate(&crypto2.CertificateTemplate{
				Organization:      "oe",
				Name:              "",
				Domains:           []string{box.params.Domain},
				IPs:               []net.IP{net.ParseIP(box.params.Ip)},
				Expiry:            time.Hour * 24 * 370,
				PublicKey:         &pub,
				SignerPrivateKey:  box.privateKey,
				SignerCertificate: nil,
			})
			if err != nil {
				return fmt.Errorf("could not generate CA cert: %s", err)
			}

		} else {
			if box.caClientAuthentication == nil {
				parts := strings.Split(box.params.CACredentials, ":")
				box.caClientAuthentication = authentication.NewGRPCBasic(parts[0], parts[1])
			}

			conn, err := grpc.Dial(box.params.CAAddress, grpc.WithTransportCredentials(box.caGRPCTransportCredentials), grpc.WithPerRPCCredentials(box.caClientAuthentication))
			if err != nil {
				return err
			}

			client := pb.NewCSRClient(conn)
			rsp, err := client.SignCertificate(context.Background(), &pb.SignCertificateRequest{
				Csr: &pb.CSRData{
					Domains:   []string{box.params.Domain},
					Addresses: []string{box.params.Ip},
					Subject:   strcase.ToDelimited(box.params.Name, '.'),
					PublicKey: elliptic.Marshal(elliptic.P256(), pub.X, pub.Y),
				},
			})
			if err != nil {
				return fmt.Errorf("could not sign certificate: %s", err)
			}

			box.cert, err = x509.ParseCertificate([]byte(rsp.RawCertificate))
			if err != nil {
				return err
			}
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

func (box *Box) serverTLS() *tls.Config {
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
		err = box.loadKeyPair()
		if err != nil {
			return nil, err
		}

		if tc == nil {
			if web {
				tc = box.serverTLS()
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

	if box.params.CAAddress != "" || box.params.CACertPath != "" || box.params.CACredentials != "" {
		if box.params.CAAddress == "" || box.params.CACertPath == "" || box.params.CACredentials == "" {
			return fmt.Errorf("command line: --ca-addr must always be provided with --ca-cert and --ca-cred")
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

func (box *Box) host() string {
	if box.params.Domain != "" {
		return box.params.Domain
	}
	return box.params.Ip
}

func (box *Box) Context() context.Context {
	return box.ctx
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

func (box *Box) CACertificate() *x509.Certificate {
	return box.caCert
}

func (box *Box) CAClientAuthentication() credentials.PerRPCCredentials {
	return box.caClientAuthentication
}

func (box *Box) CAClientTransportCredentials() credentials.TransportCredentials {
	return box.caGRPCTransportCredentials
}

func (box *Box) ServiceCert() *x509.Certificate {
	return box.cert
}

func (box *Box) ServiceKey() crypto.PrivateKey {
	return box.privateKey
}

func (box *Box) Init(opts ...InitOption) error {
	var err error
	options := &initOptions{}
	for _, opt := range opts {
		opt(options)
	}

	box.boxDir = filepath.Join(box.params.Dir, "box")
	_ = os.MkdirAll(box.boxDir, os.ModePerm)

	if box.params.CertificatePath != "" {
		box.cert, err = crypto2.LoadCertificate(box.params.CACertPath)
		if err != nil {
			return fmt.Errorf("could not load service certificate: %s", err)
		}

		box.privateKey, err = crypto2.LoadPrivateKey(nil, box.params.KeyPath)
		if err != nil {
			return fmt.Errorf("could not load service private key: %s", err)
		}
	}

	if box.params.CA {
		err = box.loadKeyPair()
		if err != nil {
			return fmt.Errorf("could not load CA key pair: %s", err)
		}

	} else if box.params.CAAddress != "" {
		box.caCert, err = crypto2.LoadCertificate(box.params.CACertPath)
		if err != nil {
			return fmt.Errorf("could not load authority certificate: %s", err)
		}

		box.caGRPCTransportCredentials, err = credentials.NewClientTLSFromFile(box.params.CACertPath, "")
		if err != nil {
			return fmt.Errorf("could not create authority client credentials: %s", box.params.CACertPath)
		}

		parts := strings.Split(box.params.CACredentials, ":")
		box.caClientAuthentication = authentication.NewGRPCBasic(parts[0], parts[1])

		err = box.loadKeyPair()
		if err != nil {
			return err
		}
	}

	syncedRegistry := NewSyncedRegistryServer()
	if box.params.CAAddress != "" {
		err = syncedRegistry.Serve(box.host()+RegistryDefaultHost, box.serverMutualTLS())

	} else if box.params.CA {
		err = syncedRegistry.Serve(box.host()+RegistryDefaultHost, box.serverTLS())

	} else {
		err = syncedRegistry.Serve(box.host()+RegistryDefaultHost, nil)
	}

	if err != nil {
		log.Println("An instance of registry might already be running on this machine")
		syncedRegistry = nil
	}

	if box.params.RegistryAddress == "" {
		box.params.RegistryAddress = RegistryDefaultHost
	}

	parts := strings.Split(box.params.RegistryAddress, ":")
	if len(parts) != 2 {
		return errors.New("malformed registry address. Should be like HOST:PORT")
	}

	registryHost := parts[0]
	if syncedRegistry == nil || registryHost != "" && registryHost != RegistryDefaultHost && registryHost != box.host() {
		var syncedRegistry *SyncedRegistry
		var tc *tls.Config
		if box.params.RegistrySecure {
			tc = box.clientMutualTLS()
			syncedRegistry = NewSyncedRegistryClient(box.params.RegistryAddress, tc)
		} else {
			syncedRegistry = NewSyncedRegistryClient(box.params.RegistryAddress, nil)
		}
		box.registry = syncedRegistry
	}

	if box.params.CA {
		return box.startCA(options.credentialsProvider)
	}
	return nil
}

func (box *Box) startCA(credentialsProvider func(...string) string) error {
	var tc *tls.Config
	certPEMBytes, _ := crypto2.PEMEncodeCertificate(box.cert)
	keyPEMBytes, _ := crypto2.PEMEncodeKey(box.privateKey)
	tlsCert, err := tls.X509KeyPair(certPEMBytes, keyPEMBytes)
	if err == nil {
		clientCAs := x509.NewCertPool()
		clientCAs.AddCert(box.cert)
		tc = &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			ClientCAs:    clientCAs,
			ClientAuth:   tls.VerifyClientCertIfGiven,
		}
	} else {
		log.Println("could not load TLS configs")
		return err
	}

	address := fmt.Sprintf("%s:9090", box.Ip())
	listener, err := tls.Listen("tcp", address, tc)
	if err != nil {
		return err
	}

	log.Printf("starting CA.gRPC at %s", address)
	var opts []grpc.ServerOption
	interceptor := interceptors.NewChainedInterceptor(map[string]*interceptors.InterceptRule{
		"SignCertificate": {
			Secure: true,
			Links:  []string{interceptors.BasicValidator},
		},
	}, interceptors.NewBasic("box-ca", credentialsProvider))
	opts = append(opts, grpc.StreamInterceptor(interceptor.InterceptStream), grpc.UnaryInterceptor(interceptor.InterceptUnary))
	gs := grpc.NewServer(opts...)
	pb.RegisterCSRServer(gs, &csrServerHandler{
		PrivateKey:  box.privateKey,
		Certificate: box.cert,
	})
	go gs.Serve(listener)
	return nil
}

func (box *Box) StartGatewayGRPCMapping(name string, g *server.GatewayServiceMapping) error {
	if box.registry == nil {
		box.serverMutex.Lock()
		defer box.serverMutex.Unlock()

		info, err := box.registry.GetService(box.params.Namespace + ":" + name)
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

	listener, err := box.listen(false, true, g.Port, g.Tls)
	if err != nil {
		return err
	}
	address := listener.Addr().String()
	if g.Info == nil {
		g.Info = new(pb.Info)
	}

	log.Printf("starting %s.gRPC at %s", name, address)
	var opts []grpc.ServerOption
	if g.Interceptor != nil {
		opts = append(opts, grpc.StreamInterceptor(g.Interceptor.InterceptStream), grpc.UnaryInterceptor(g.Interceptor.InterceptUnary))
	}

	srv := grpc.NewServer(opts...)
	rs := new(runningService)
	rs.service = g
	rs.server = srv
	box.services[name] = rs

	g.RegisterHandlerFunc(srv)
	go srv.Serve(listener)

	if g.Info != nil && box.registry != nil {
		g.Info.Namespace = box.params.Namespace
		g.Info.ServiceNode.Address = address
		g.Info.ServiceNode.Protocol = pb.Protocol_Grpc
		g.Info.ServiceNode.Security = pb.Security_MutualTLS
		g.Info.ServiceNode.Ttl = 0
		rs.registryId, err = box.registry.RegisterService(g.Info)
		if err != nil {
			log.Println("could not register service")
		}
	}
	return nil
}

func (box *Box) StopService(name string) {
	box.serverMutex.Lock()
	defer box.serverMutex.Unlock()
	rs := box.services[name]
	delete(box.services, name)
	if rs != nil && box.registry != nil {
		err := box.registry.DeregisterService(rs.registryId)
		if err != nil {
			log.Println("could not deregister service:", name)
		}
		rs.server.Stop()
	}
}

func (box *Box) stopServices() error {
	box.serverMutex.Lock()
	defer box.serverMutex.Unlock()
	if box.registry != nil {
		for name, rs := range box.services {
			rs.server.Stop()
			err := box.registry.DeregisterService(rs.registryId)
			if err != nil {
				log.Println("could not deregister service:", name)
			}
		}
	}
	box.services = map[string]*runningService{}
	return nil
}

func (box *Box) stopGateways() error {
	box.serverMutex.Lock()
	defer box.serverMutex.Unlock()
	for name, srv := range box.gateways {
		err := srv.Close()
		log.Printf("name: %s\t state:stopped\t error:%s\n", name, err)
	}
	return nil
}

func (box *Box) Stop() {
	if box.registry != nil {
		box.registry.Stop()
	}
	_ = box.stopServices()
	_ = box.stopGateways()
}
