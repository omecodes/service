package service

import (
	"github.com/spf13/cobra"
)

const (
	CmdFlagIP                = "ip"
	CmdFlagExternalIP        = "eip"
	CmdFlagName              = "name"
	CmdFlagServiceDomain     = "dn"
	CmdFlagAdditionalDomains = "odn"
	CmdFlagCert              = "cert"
	CmdFlagKey               = "key"
	CmdFlagCAAddr            = "ca-addr"
	CmdFlagCACert            = "ca-cert"
	CmdFlagCAApiKey          = "ca-api-key"
	CmdFlagCAApiSecret       = "ca-api-secret"
	CmdFlagRegistry          = "reg"
)

func CMD(use string, box *Box) *cobra.Command {
	command := &cobra.Command{
		Use:   use,
		Short: use,
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}

	flags := command.PersistentFlags()

	flags.StringVar(&box.options.name, CmdFlagName, "", "Unique name in registryAddress group")
	flags.StringVar(&box.options.certificateFilename, CmdFlagCert, "", "Public certificate path")
	flags.StringVar(&box.options.keyFilename, CmdFlagKey, "", "Private key path")

	flags.StringVar(&box.options.regAddr, CmdFlagRegistry, "", "Registry server address")

	flags.StringVar(&box.options.netIP, CmdFlagIP, "", "Bind ip address. Must match the domain if provided and no eip is provided")
	flags.StringVar(&box.options.netExternalIP, CmdFlagExternalIP, "", "External ip. Must matching domain if provided")
	flags.StringVar(&box.options.netMainDomain, CmdFlagServiceDomain, "", "Main domain name - Used as service name")
	flags.StringArrayVar(&box.options.netDomains, CmdFlagAdditionalDomains, nil, "Additional domain name list")

	flags.StringVar(&box.options.caCertFilename, CmdFlagCACert, "", "Authority Certificate - file path")
	flags.StringVar(&box.options.caAddr, CmdFlagCAAddr, "", "Authority ServerGRPC - address location")
	flags.StringVar(&box.options.caAPIKey, CmdFlagCAApiKey, "", "Authority Credentials - authority authentication credentials")
	flags.StringVar(&box.options.caAPISecret, CmdFlagCAApiSecret, "", "Authority Credentials - authority authentication credentials")
	return command
}

func SetCMDFlags(cmd *cobra.Command, box *Box, ignoreFlagName bool) {
	flags := cmd.PersistentFlags()

	if !ignoreFlagName {
		flags.StringVar(&box.options.name, CmdFlagName, "", "Unique name in registryAddress group")
	}
	flags.StringVar(&box.options.certificateFilename, CmdFlagCert, "", "Public certificate path")
	flags.StringVar(&box.options.keyFilename, CmdFlagKey, "", "Private key path")

	flags.StringVar(&box.options.regAddr, CmdFlagRegistry, "", "Registry server address")

	flags.StringVar(&box.options.netIP, CmdFlagIP, "", "Bind ip address. Must match the domain if provided and no eip is provided")
	flags.StringVar(&box.options.netExternalIP, CmdFlagExternalIP, "", "External ip. Must matching domain if provided")
	flags.StringVar(&box.options.netMainDomain, CmdFlagServiceDomain, "", "Main domain name - Used as service name")
	flags.StringArrayVar(&box.options.netDomains, CmdFlagAdditionalDomains, nil, "Additional domain name list")

	flags.StringVar(&box.options.caCertFilename, CmdFlagCACert, "", "Authority Certificate - file path")
	flags.StringVar(&box.options.caAddr, CmdFlagCAAddr, "", "Authority ServerGRPC - address location")
	flags.StringVar(&box.options.caAPIKey, CmdFlagCAApiKey, "", "Authority Credentials - authority authentication credentials")
	flags.StringVar(&box.options.caAPISecret, CmdFlagCAApiSecret, "", "Authority Credentials - authority authentication credentials")
}
