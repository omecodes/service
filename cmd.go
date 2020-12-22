package service

import (
	"github.com/spf13/cobra"
)

const (
	CmdFlagAutonomous        = "auto"
	CmdFlagIP                = "ip"
	CmdFlagExternalIP        = "eip"
	CmdFlagName              = "name"
	CmdFlagServiceDomain     = "dn"
	CmdFlagAdditionalDomains = "odn"
	CmdFlagCert              = "cert"
	CmdFlagKey               = "key"
	CmdFlagAcme              = "acme"
	CmdFlagCA                = "ca"
	CmdFlagCAAddr            = "ca-addr"
	CmdFlagCACert            = "ca-cert"
	CmdFlagCACred            = "ca-cred"
	CmdFlagNoRegistry        = "no-reg"
	CmdFlagRegistry          = "reg"
	CmdFlagRegistrySecure    = "reg-tls"
	CmdFlagRegistryServer    = "reg-server"
)

func CMD(use string, params *Params) *cobra.Command {
	command := &cobra.Command{
		Use:   use,
		Short: use,
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}

	flags := command.PersistentFlags()

	flags.StringVar(&params.Name, CmdFlagName, "", "Unique name in registryAddress group")
	flags.StringVar(&params.CertificatePath, CmdFlagCert, "", "Public certificate path")
	flags.StringVar(&params.KeyPath, CmdFlagKey, "", "Private key path")

	flags.StringVar(&params.RegistryAddress, CmdFlagRegistry, "", "Registry server address")

	flags.StringVar(&params.Ip, CmdFlagIP, "", "Bind ip address. Must match the domain if provided and no eip is provided")
	flags.StringVar(&params.Ip, CmdFlagExternalIP, "", "External ip. Must matching domain if provided")
	flags.StringVar(&params.Domain, CmdFlagServiceDomain, "", "Main domain name - Used as service name")
	flags.StringArrayVar(&params.OtherDomains, CmdFlagAdditionalDomains, nil, "Additional domain name list")

	flags.StringVar(&params.CACertPath, CmdFlagCACert, "", "Authority Certificate - file path")
	flags.StringVar(&params.CAAddress, CmdFlagCAAddr, "", "Authority ServerGRPC - address location")
	flags.StringVar(&params.CACredentials, CmdFlagCACred, "", "Authority Credentials - authority authentication credentials")
	return command
}

func SetCMDFlags(cmd *cobra.Command, params *Params, ignoreFlagName bool) {
	flags := cmd.PersistentFlags()

	if !ignoreFlagName {
		flags.StringVar(&params.Name, CmdFlagName, "", "Unique name in registryAddress group")
	}
	flags.StringVar(&params.CertificatePath, CmdFlagCert, "", "Public certificate path")
	flags.StringVar(&params.KeyPath, CmdFlagKey, "", "Private key path")

	flags.StringVar(&params.RegistryAddress, CmdFlagRegistry, "", "Registry server address")

	flags.StringVar(&params.Ip, CmdFlagIP, "", "Bind ip address. Must match the domain if provided and no eip is provided")
	flags.StringVar(&params.Ip, CmdFlagExternalIP, "", "External ip. Must matching domain if provided")
	flags.StringVar(&params.Domain, CmdFlagServiceDomain, "", "Main domain name - Used as service name")
	flags.StringArrayVar(&params.OtherDomains, CmdFlagAdditionalDomains, nil, "Additional domain name list")

	flags.StringVar(&params.CACertPath, CmdFlagCACert, "", "Authority Certificate - file path")
	flags.StringVar(&params.CAAddress, CmdFlagCAAddr, "", "Authority ServerGRPC - address location")
	flags.StringVar(&params.CACredentials, CmdFlagCACred, "", "Authority Credentials - authority authentication credentials")
}
