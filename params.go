package service

type Params struct {
	Name            string
	Dir             string
	Domain          string
	Ip              string
	CertificatePath string
	KeyPath         string

	RegistryAddress string
	RegistrySecure  bool
	Namespace       string
	RegistryID      string
	StartRegistry   bool

	IsCA          bool
	CA            string
	CACertPath    string
	CACredentials string
}
