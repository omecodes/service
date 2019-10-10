package service

import (
	"github.com/spf13/cobra"
)

const (
	CmdFlagAuthority      = "a-grpc"
	CmdFlagIP             = "ip"
	CmdFlagName           = "name"
	CmdFlagDir            = "dir"
	CmdFlagDomain         = "domain"
	CmdFlagCert           = "cert"
	CmdFlagKey            = "key"
	CmdFlagNamespace      = "ns"
	CmdFlagAuthorityCert  = "a-cert"
	CmdFlagAuthorityCred  = "a-cred"
	CmdFlagRegistry       = "reg"
	CmdFlagRegistrySecure = "reg-secure"
	CmdFlagGRPC           = "grpc"
	CmdFlagHTTP           = "http"
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
	command.PersistentFlags().StringVar(&params.RegistryAddress, CmdFlagRegistry, "", "Registry Server - address location")
	command.PersistentFlags().BoolVar(&params.RegistrySecure, CmdFlagRegistrySecure, false, "Registry Secure Mode - enable secure connection to registry")
	command.PersistentFlags().StringVar(&params.Namespace, CmdFlagNamespace, "", "Namespace - Group identifier for registryAddress")
	command.PersistentFlags().StringVar(&params.Ip, CmdFlagIP, "", "Network - ip address to listen to. Must matching domain if provided")
	command.PersistentFlags().StringVar(&params.Domain, CmdFlagDomain, "", "Domain - Domain name to bind to")
	command.PersistentFlags().StringVar(&params.CaCertPath, CmdFlagAuthorityCert, "", "Authority Certificate - file path")
	command.PersistentFlags().StringVar(&params.CaGRPC, CmdFlagAuthority, "", "Authority ServerGRPC - address location")
	command.PersistentFlags().StringVar(&params.CaCredentials, CmdFlagAuthorityCred, "", "Authority Credentials - authority authentication credentials")
	return command
}
