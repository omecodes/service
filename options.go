package service

import (
	"crypto"
	"crypto/x509"
)

type options struct {
	name       string
	workingDir string

	caCert         *x509.Certificate
	caKey          crypto.PrivateKey
	caCertFilename string
	caAddr         string
	caAPIKey       string
	caAPISecret    string

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

func (opts *options) override(opt ...Option) {
	for _, o := range opt {
		o(opts)
	}
}

func (opts *options) Name() string {
	return opts.name
}

func (opts *options) Domain() string {
	return opts.netMainDomain
}

func (opts *options) IP() string {
	return opts.netIP
}

func (opts *options) Dir() string {
	return opts.workingDir
}

func (opts *options) CertificateFilename() string {
	return opts.certificateFilename
}

func (opts *options) KeyFilename() string {
	return opts.keyFilename
}

func (opts *options) Host() string {
	if opts.netMainDomain != "" {
		return opts.netMainDomain
	}

	if opts.netExternalIP != "" {
		return opts.netExternalIP
	}

	return opts.netIP
}

func (opts *options) BindIP() string {
	return opts.netIP
}

func (opts *options) ExternalIP() string {
	return opts.netExternalIP
}

func (opts *options) IpList() []string {
	var l []string

	if opts.netIP != "" {
		l = append(l, opts.netIP)
	}

	if opts.netExternalIP != "" && opts.netExternalIP != opts.netIP {
		l = append(l, opts.netExternalIP)
	}
	return l
}

func (opts *options) ServiceCert() *x509.Certificate {
	return opts.cert
}

func (opts *options) ServiceKey() crypto.PrivateKey {
	return opts.key
}

func (opts *options) CACertificate() *x509.Certificate {
	return opts.caCert
}

// Option is an [options] object handler function
type Option func(*options)

func Name(name string) Option {
	return func(o *options) {
		o.name = name
	}
}

func Dir(dirname string) Option {
	return func(o *options) {
		o.workingDir = dirname
	}
}

func CACert(cert *x509.Certificate) Option {
	return func(o *options) {
		o.caCert = cert
	}
}

func CAKey(key crypto.PrivateKey) Option {
	return func(o *options) {
		o.caKey = key
	}
}

func CACertFile(filename string) Option {
	return func(o *options) {
		o.caCertFilename = filename
	}
}

func CAKeyFIle(filename string) Option {
	return func(o *options) {
		o.caKey = filename
	}
}

func CAAddr(addr string) Option {
	return func(o *options) {
		o.caAddr = addr
	}
}

// CAApiKey returns function that sets the API access key in options
func CAApiKey(apiKey string) Option {
	return func(o *options) {
		o.caAPIKey = apiKey
	}
}

func CAApiSecret(apiSecret string) Option {
	return func(o *options) {
		o.caAPISecret = apiSecret
	}
}

func RegAddr(addr string) Option {
	return func(o *options) {
		o.regAddr = addr
	}
}

func RegApiKey(apiKey string) Option {
	return func(o *options) {
		o.regAPIKey = apiKey
	}
}

func RegApiSecret(apiSecret string) Option {
	return func(o *options) {
		o.regAPISecret = apiSecret
	}
}

func Log(Filename string) Option {
	return func(o *options) {
		o.logFile = Filename
	}
}

func Domain(domain string, others ...string) Option {
	return func(o *options) {
		o.netMainDomain = domain
		o.netDomains = others
	}
}

func Ip(ip string) Option {
	return func(o *options) {
		o.netIP = ip
	}
}

func ExternalIp(ip string) Option {
	return func(o *options) {
		o.netExternalIP = ip
	}
}

func Cert(cert *x509.Certificate) Option {
	return func(o *options) {
		o.cert = cert
	}
}

func Key(key crypto.PrivateKey) Option {
	return func(o *options) {
		o.key = key
	}
}

func CertFile(filename string) Option {
	return func(o *options) {
		o.certificateFilename = filename
	}
}

func KeyFIle(filename string) Option {
	return func(o *options) {
		o.keyFilename = filename
	}
}
