package service

import (
	"context"
	"errors"
	"fmt"
	"github.com/zoenion/service/connection"
	pb "github.com/zoenion/service/proto"
	"github.com/zoenion/service/server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type runningService struct {
	service    *server.Service
	registryId string
	server     *grpc.Server
}

func GRPCConnectionDialer(ctx context.Context, serviceType pb.Type) (connection.Dialer, error) {
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
		if info.ServiceNode != nil {
			tlsConf := ClientTLSConfig(ctx)
			if tlsConf == nil {
				return connection.NewDialer(info.ServiceNode.Address), nil
			} else {
				return connection.NewDialer(info.ServiceNode.Address, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf))), nil
			}
		}
	}
	return nil, fmt.Errorf("no service of type %s that supports gRPC has been found", serviceType)
}
