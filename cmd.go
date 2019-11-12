package service

import (
	"github.com/spf13/cobra"
)

const (
	CmdFlagAutonomous     = "auto"
	CmdFlagIP             = "ip"
	CmdFlagExternalIP     = "eip"
	CmdFlagName           = "name"
	CmdFlagDomain         = "domain"
	CmdFlagCert           = "cert"
	CmdFlagKey            = "key"
	CmdFlagNamespace      = "ns"
	CmdFlagCA             = "ca"
	CmdFlagCAAddr         = "ca-addr"
	CmdFlagCACert         = "ca-cert"
	CmdFlagCACred         = "ca-cred"
	CmdFlagRegistry       = "reg"
	CmdFlagRegistrySecure = "reg-secure"
	CmdFlagStartRegistry  = "start-reg"
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

	flags.BoolVar(&params.Autonomous, CmdFlagAutonomous, false, "Autonomous mode - Needs no CA nor registry")

	flags.StringVar(&params.Name, CmdFlagName, "", "Unique name in registryAddress group")
	flags.StringVar(&params.CertificatePath, CmdFlagCert, "", "Public certificate path")

	flags.StringVar(&params.KeyPath, CmdFlagKey, "", "Private key path")
	flags.StringVar(&params.RegistryAddress, CmdFlagRegistry, "", "Start registry server - address location")
	flags.BoolVar(&params.StartRegistry, CmdFlagStartRegistry, false, "Registry Server - address location")
	flags.BoolVar(&params.RegistrySecure, CmdFlagRegistrySecure, false, "Registry Secure Mode - enable secure connection to registry")
	flags.StringVar(&params.Namespace, CmdFlagNamespace, "", "Namespace - Group identifier for registryAddress")

	flags.StringVar(&params.Ip, CmdFlagIP, "", "Bind ip address. Must match the domain if provided and no eip is provided")
	flags.StringVar(&params.Ip, CmdFlagExternalIP, "", "External ip. Must matching domain if provided")
	flags.StringVar(&params.Domain, CmdFlagDomain, "", "Domain name")

	flags.BoolVar(&params.CA, CmdFlagCA, false, "Is CA - Runs service as CA")
	flags.StringVar(&params.CACertPath, CmdFlagCACert, "", "Authority Certificate - file path")
	flags.StringVar(&params.CAAddress, CmdFlagCAAddr, "", "Authority ServerGRPC - address location")
	flags.StringVar(&params.CACredentials, CmdFlagCACred, "", "Authority Credentials - authority authentication credentials")
	return command
}
