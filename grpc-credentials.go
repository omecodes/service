package service

import (
	ome "github.com/omecodes/libome"
	"google.golang.org/grpc/credentials"
	"strings"
)

func (box *Box) OmeBasicClientCredentials() credentials.PerRPCCredentials {
	if box.caClientAuthentication == nil {
		parts := strings.Split(box.params.CACredentials, ":")
		box.caClientAuthentication = ome.NewGRPCBasic(parts[0], parts[1])
	}
	return box.caClientAuthentication
}

func (box *Box) OmeProxyBasicClientCredentials() credentials.PerRPCCredentials {
	parts := strings.Split(box.params.CACredentials, ":")
	return ome.NewGRPCProxy(parts[0], parts[1])
}

func (box *Box) CAClientTransportCredentials() credentials.TransportCredentials {
	return box.caGRPCTransportCredentials
}
