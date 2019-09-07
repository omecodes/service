package service

import (
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var (
	Vendor  = "Zoenion"
	AppName = strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe")
)

func CMD(use string, service Service) *cobra.Command {
	params := BoxParams{}
	var cfgDir, cfgName string

	configureCMD := &cobra.Command{
		Use:   "configure",
		Short: "configure node",
		Run: func(cmd *cobra.Command, args []string) {
			if cfgDir == "" {
				d := getDir()
				if err := d.Create(); err != nil {
					log.Fatalln("could not initialize configs dir:", err)
				}
				cfgDir = d.path
			}

			if err := validateConfVars(cfgName, cfgDir); err != nil {
				log.Fatalln(err)
			}
			err := service.Configure(cfgName, cfgDir)
			if err != nil {
				log.Fatalln(err)
			}
		},
	}
	configureCMD.PersistentFlags().StringVar(&cfgName, CmdFlagName, "", "Unique name in registryAddress group")
	configureCMD.PersistentFlags().StringVar(&cfgDir, CmdFlagDir, "", "Configs directory path")

	startCMD := &cobra.Command{
		Use:   "start",
		Short: "start node",
		Run: func(cmd *cobra.Command, args []string) {
			Run(service, params)
		},
	}
	startCMD.PersistentFlags().StringVar(&params.Name, CmdFlagName, "", "Unique name in registryAddress group")
	startCMD.PersistentFlags().StringVar(&params.Name, CmdFlagDir, "", "Configs directory path")
	startCMD.PersistentFlags().StringVar(&params.CertificatePath, CmdFlagCert, "", "Public certificate path")
	startCMD.PersistentFlags().StringVar(&params.KeyPath, CmdFlagKey, "", "Private key path")
	startCMD.PersistentFlags().StringVar(&params.GatewayGRPCPort, CmdFlagGRPC, "", "Grpc Port: gRPC port")
	startCMD.PersistentFlags().StringVar(&params.GatewayHTTPPort, CmdFlagHTTP, "", "Web Port: Web port")
	startCMD.PersistentFlags().StringVar(&params.RegistryAddress, CmdFlagRegistry, "", "Registry Server - address location")
	startCMD.PersistentFlags().BoolVar(&params.RegistrySecure, CmdFlagRegistrySecure, false, "Registry Secure Mode - enable secure connection to registry")
	startCMD.PersistentFlags().StringVar(&params.Namespace, CmdFlagNamespace, "", "Namespace - Group identifier for registryAddress")
	startCMD.PersistentFlags().StringVar(&params.Ip, CmdFlagIP, "", "Network - ip address to listen to. Must matching domain if provided")
	startCMD.PersistentFlags().StringVar(&params.Domain, CmdFlagDomain, "", "Domain - Domain name to bind to")
	startCMD.PersistentFlags().StringVar(&params.CaCertPath, CmdFlagAuthorityCert, "", "Authority Certificate - file path")
	startCMD.PersistentFlags().StringVar(&params.CaGRPC, CmdFlagAuthority, "", "Authority Grpc - address location")
	startCMD.PersistentFlags().StringVar(&params.CaCredentials, CmdFlagAuthorityCred, "", "Authority Credentials - authority authentication credentials")

	command := &cobra.Command{
		Use:   use,
		Short: use,
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}
	command.AddCommand(configureCMD)
	command.AddCommand(startCMD)
	return command
}

func validateConfVars(name, dir string) error {
	if dir == "" {
		d := getDir()
		dir = d.Path()
		if err := d.Create(); err != nil {
			log.Printf("could not create %s. Might not be writeable\n", dir)
			return err
		}

	} else {
		var err error
		dir, err = filepath.Abs(dir)
		if err != nil {
			log.Printf("could not find %s\n", dir)
			return err
		}
	}
	return nil
}
