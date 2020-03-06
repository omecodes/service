package service

import (
	"github.com/zoenion/common/errors"
	"github.com/zoenion/service/connection"
	pb "github.com/zoenion/service/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"log"
)

func (box *Box) dialToService(serviceType pb.Type, selectors ...pb.Selector) (*grpc.ClientConn, error) {
	infoList, err := box.Registry().GetOfType(serviceType)
	if err != nil {
		return nil, err
	}

	var selection []*pb.Info
	if selectors != nil {
		for _, selector := range selectors {
			for _, item := range infoList {
				if selector(item) {
					selection = append(selection, item)
				}
			}
		}
	} else {
		selection = infoList
	}

	var dialer connection.Dialer
	for _, info := range selection {
		// Search for cached connection dialer
		for _, node := range info.Nodes {
			conn := box.dialFromCache(node.Address)
			if conn != nil {
				return conn, nil
			}
		}

		// if no existing connection dialer found, dial new one
		for _, node := range info.Nodes {
			tlsConf := box.ClientMutualTLS()
			if tlsConf == nil {
				dialer = connection.NewDialer(node.Address)
			} else {
				dialer = connection.NewDialer(node.Address, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)))
			}

			conn, err := dialer.Dial()
			if err != nil {
				log.Printf("could not connect to gRPC://%s/%s@%s\n", info.Type, node.Name, node.Address)
			} else {
				log.Printf("connected to gRPC://%s/%s@%s\n", info.Type, node.Name, node.Address)
				box.addDialerToCache(node.Address, dialer)
				return conn, err
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

func (box *Box) addDialerToCache(addr string, dialer connection.Dialer) {
	box.dialerMutex.Lock()
	defer box.dialerMutex.Unlock()

	box.dialerCache[addr] = dialer
}
