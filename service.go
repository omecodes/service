package service

import (
	"github.com/zoenion/service/proto"
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

type BoxConfigs struct {
	Type    proto.Type
	Web     *Web
	Grpc    *Grpc
	Options []Option
	Meta    map[string]string
}

type Service interface {
	Configure(name, dir string) error
	BoxConfigsLoader
}
