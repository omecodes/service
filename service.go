package service

import (
	"context"
	"errors"
	"fmt"
	"github.com/shibukawa/configdir"
	"github.com/zoenion/service/connection"
	"github.com/zoenion/service/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"os"
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

type Configs struct {
	Type    proto.Type
	HTTP    *ServerHTTP
	GRPC    *ServerGRPC
	Options []Option
	Meta    map[string]string
}

type Service interface {
	Configure(name, dir string) error
	BoxConfigsLoader
}

type ConfDir struct {
	path string
}

func (d *ConfDir) Create() error {
	return os.MkdirAll(d.path, os.ModePerm)
}

func (d *ConfDir) Path() string {
	return d.path
}

func getDir() *ConfDir {
	dirs := configdir.New(Vendor, AppName)
	appData := dirs.QueryFolders(configdir.Global)[0]
	return &ConfDir{appData.Path}
}

func GRPCConnectionDialer(ctx context.Context, serviceType proto.Type) (connection.GRPCDialer, error) {
	reg := Registry(ctx)
	if reg == nil {
		return nil, errors.New("no registry configured")
	}

	infos, err := reg.GetOfType(serviceType)
	if err != nil {
		return nil, err
	}

	if len(infos) == 0 {
		return nil, errors.New("not found")
	}

	for _, info := range infos {
		for _, n := range info.Nodes {
			if n.Protocol == proto.Protocol_Grpc {
				tlsConf := ClientTLSConfig(ctx)
				if tlsConf == nil {
					return connection.NewGRPCDialer(n.Address), nil
				} else {
					return connection.NewGRPCDialer(n.Address, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf))), nil
				}
			}
		}
	}
	return nil, fmt.Errorf("no service of type %s that supports gRPC has been found", serviceType)
}
