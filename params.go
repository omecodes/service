package service

type BoxParams struct {
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

	CaGRPC        string
	CaCertPath    string
	CaCredentials string

	GatewayGRPCPort string
	GatewayHTTPPort string
}
