package service

import (
	"crypto"
	"crypto/x509"
	"github.com/omecodes/discover"
	ome "github.com/omecodes/libome"
)

type Options struct {
	name       string
	workingDir string

	caCert         *x509.Certificate
	caKey          crypto.PrivateKey
	caCertFilename string
	caAddr         string
	caAPIKey       string
	caAPISecret    string

	registry     ome.Registry
	regAddr      string
	regAPIKey    string
	regAPISecret string

	logFile string

	netMainDomain string
	netDomains    []string
	netIP         string
	netExternalIP string

	cert                *x509.Certificate
	key                 crypto.PrivateKey
	certificateFilename string
	keyFilename         string
}

func (opts *Options) override(opt ...Option) {
	for _, o := range opt {
		o(opts)
	}
}

func (opts *Options) Name() string {
	return opts.name
}

func (opts *Options) Domain() string {
	return opts.netMainDomain
}

func (opts *Options) IP() string {
	return opts.netIP
}

func (opts *Options) Dir() string {
	return opts.workingDir
}

func (opts *Options) CertificateFilename() string {
	return opts.certificateFilename
}

func (opts *Options) KeyFilename() string {
	return opts.keyFilename
}

func (opts *Options) Host() string {
	if opts.netMainDomain != "" {
		return opts.netMainDomain
	}

	if opts.netExternalIP != "" {
		return opts.netExternalIP
	}

	return opts.netIP
}

func (opts *Options) BindIP() string {
	return opts.netIP
}

func (opts *Options) ExternalIP() string {
	return opts.netExternalIP
}

func (opts *Options) IpList() []string {
	var l []string

	if opts.netIP != "" {
		l = append(l, opts.netIP)
	}

	if opts.netExternalIP != "" && opts.netExternalIP != opts.netIP {
		l = append(l, opts.netExternalIP)
	}
	return l
}

func (opts *Options) Domains() []string {
	return append(opts.netDomains, opts.netMainDomain)
}

func (opts *Options) ServiceCert() *x509.Certificate {
	return opts.cert
}

func (opts *Options) ServiceKey() crypto.PrivateKey {
	return opts.key
}

func (opts *Options) CACertificate() *x509.Certificate {
	return opts.caCert
}

func (opts *Options) Registry() ome.Registry {
	if opts.registry == nil {
		opts.registry = discover.NewZebouClient(opts.regAddr, opts.ClientMutualTLS())
	}
	return opts.registry
}

// Option is an [Options] object handler function
type Option func(*Options)

func Name(name string) Option {
	return func(o *Options) {
		o.name = name
	}
}

func Dir(dirname string) Option {
	return func(o *Options) {
		o.workingDir = dirname
	}
}

func CACert(cert *x509.Certificate) Option {
	return func(o *Options) {
		o.caCert = cert
	}
}

func CAKey(key crypto.PrivateKey) Option {
	return func(o *Options) {
		o.caKey = key
	}
}

func CACertFile(filename string) Option {
	return func(o *Options) {
		o.caCertFilename = filename
	}
}

func CAKeyFIle(filename string) Option {
	return func(o *Options) {
		o.caKey = filename
	}
}

func CAAddr(addr string) Option {
	return func(o *Options) {
		o.caAddr = addr
	}
}

// CAApiKey returns function that sets the API access key in options
func CAApiKey(apiKey string) Option {
	return func(o *Options) {
		o.caAPIKey = apiKey
	}
}

func CAApiSecret(apiSecret string) Option {
	return func(o *Options) {
		o.caAPISecret = apiSecret
	}
}

func RegAddr(addr string) Option {
	return func(o *Options) {
		o.regAddr = addr
	}
}

func RegApiKey(apiKey string) Option {
	return func(o *Options) {
		o.regAPIKey = apiKey
	}
}

func RegApiSecret(apiSecret string) Option {
	return func(o *Options) {
		o.regAPISecret = apiSecret
	}
}

func Log(Filename string) Option {
	return func(o *Options) {
		o.logFile = Filename
	}
}

func Domain(domain string, others ...string) Option {
	return func(o *Options) {
		o.netMainDomain = domain
		o.netDomains = others
	}
}

func Ip(ip string) Option {
	return func(o *Options) {
		o.netIP = ip
	}
}

func ExternalIp(ip string) Option {
	return func(o *Options) {
		o.netExternalIP = ip
	}
}

func Cert(cert *x509.Certificate) Option {
	return func(o *Options) {
		o.cert = cert
	}
}

func Key(key crypto.PrivateKey) Option {
	return func(o *Options) {
		o.key = key
	}
}

func CertFile(filename string) Option {
	return func(o *Options) {
		o.certificateFilename = filename
	}
}

func KeyFIle(filename string) Option {
	return func(o *Options) {
		o.keyFilename = filename
	}
}
