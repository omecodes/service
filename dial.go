package service

import (
	"fmt"
	"github.com/omecodes/common/errors"
	pb "github.com/omecodes/common/ome/proto/service"
	"github.com/omecodes/common/utils/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
)

func (box *Box) dialToService(serviceType pb.Type) (*grpc.ClientConn, error) {
	infoList, err := box.Registry().GetOfType(serviceType)
	if err != nil {
		return nil, err
	}

	var selection = infoList

	var dialer Dialer
	for _, info := range selection {
		// Search for cached connection dialer
		for _, node := range info.Nodes {
			if node.Protocol == pb.Protocol_Grpc {
				conn := box.dialFromCache(node.Address)
				if conn != nil {
					return conn, nil
				}
			}
		}

		// if no existing connection dialer found, dial new one
		for _, node := range info.Nodes {
			if node.Protocol == pb.Protocol_Grpc {
				tlsConf := box.ClientMutualTLS()
				if tlsConf == nil {
					dialer = NewDialer(node.Address)
				} else {
					dialer = NewDialer(node.Address, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)))
				}

				conn, err := dialer.Dial()
				if err != nil {
					log.Error("could not connect to gRPC server", log.Err(err), log.Field("at", fmt.Sprintf("grpc://%s/%s@%s", info.Type, node.Id, node.Address)))
				} else {
					log.Info("connected to gRPC server", log.Field("at", fmt.Sprintf("grpc://%s/%s@%s", info.Type, node.Id, node.Address)))
					box.addDialerToCache(node.Address, dialer)
					return conn, err
				}
			}
		}
	}

	return nil, errors.ServiceNotAvailable
}

func (box *Box) dialFromCache(addr string) *grpc.ClientConn {
	box.dialerMutex.Lock()
	defer box.dialerMutex.Unlock()

	dialer := box.dialerCache[addr]
	if dialer != nil {
		conn, _ := dialer.Dial()
		return conn
	}
	return nil
}

func (box *Box) addDialerToCache(addr string, dialer Dialer) {
	box.dialerMutex.Lock()
	defer box.dialerMutex.Unlock()

	box.dialerCache[addr] = dialer
}

type Dialer interface {
	Dial() (*grpc.ClientConn, error)
}

type dialer struct {
	address string
	wrapped *grpc.ClientConn
	options []grpc.DialOption
}

func (g *dialer) Dial() (*grpc.ClientConn, error) {
	if g.wrapped == nil || g.wrapped.GetState() != connectivity.Ready {
		if g.wrapped != nil {
			_ = g.wrapped.Close()
		}
		var err error
		g.wrapped, err = grpc.Dial(g.address, g.options...)
		if err != nil {
			return nil, err
		}
	}
	return g.wrapped, nil
}

func NewDialer(addr string, opts ...grpc.DialOption) *dialer {
	return &dialer{
		address: addr,
		options: opts,
	}
}
