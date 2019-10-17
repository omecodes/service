package service

import (
	"github.com/spf13/cobra"
)

const (
	CmdFlagIP             = "ip"
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

	command.PersistentFlags().StringVar(&params.Name, CmdFlagName, "", "Unique name in registryAddress group")
	command.PersistentFlags().StringVar(&params.CertificatePath, CmdFlagCert, "", "Public certificate path")
	command.PersistentFlags().StringVar(&params.KeyPath, CmdFlagKey, "", "Private key path")

	command.PersistentFlags().StringVar(&params.RegistryAddress, CmdFlagRegistry, "", "Start registry server - address location")
	command.PersistentFlags().BoolVar(&params.StartRegistry, CmdFlagStartRegistry, false, "Registry Server - address location")
	command.PersistentFlags().BoolVar(&params.RegistrySecure, CmdFlagRegistrySecure, false, "Registry Secure Mode - enable secure connection to registry")
	command.PersistentFlags().StringVar(&params.Namespace, CmdFlagNamespace, "", "Namespace - Group identifier for registryAddress")

	command.PersistentFlags().StringVar(&params.Ip, CmdFlagIP, "", "Network - ip address to listen to. Must matching domain if provided")
	command.PersistentFlags().StringVar(&params.Domain, CmdFlagDomain, "", "Domain - Domain name to bind to")

	command.PersistentFlags().BoolVar(&params.CA, CmdFlagCA, false, "Is CA - Runs service as CA")
	command.PersistentFlags().StringVar(&params.CACertPath, CmdFlagCACert, "", "Authority Certificate - file path")
	command.PersistentFlags().StringVar(&params.CAAddress, CmdFlagCAAddr, "", "Authority ServerGRPC - address location")
	command.PersistentFlags().StringVar(&params.CACredentials, CmdFlagCACred, "", "Authority Credentials - authority authentication credentials")
	return command
}
