package service

import (
	"fmt"
	"github.com/omecodes/common/errors"
	"github.com/omecodes/libome"
	"github.com/omecodes/libome/logs"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
)

func (box *Box) dialToService(serviceType uint32) (*grpc.ClientConn, error) {
	reg, err := box.Registry()
	if err != nil {
		return nil, err
	}

	infoList, err := reg.GetOfType(serviceType)
	if err != nil {
		return nil, err
	}

	var selection = infoList

	var dialer Dialer
	for _, info := range selection {
		// Search for cached connection dialer
		for _, node := range info.Nodes {
			if node.Protocol == ome.Protocol_Grpc {
				conn := box.dialFromCache(node.Address)
				if conn != nil {
					return conn, nil
				}
			}
		}

		// if no existing connection dialer found, dial new one
		for _, node := range info.Nodes {
			if node.Protocol == ome.Protocol_Grpc {
				tlsConf, err := box.ClientMutualTLS()
				if err != nil {
					return nil, err
				}
				dialer = NewDialer(node.Address, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)))
				conn, err := dialer.Dial()
				if err != nil {
					logs.Error("could not connect to gRPC server", logs.Err(err), logs.Details("at", fmt.Sprintf("grpc://%s/%s@%s", info.Type, node.Id, node.Address)))
				} else {
					logs.Info("connected to gRPC server", logs.Details("at", fmt.Sprintf("grpc://%s/%s@%s", info.Type, node.Id, node.Address)))
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
