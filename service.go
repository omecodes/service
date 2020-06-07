package service

import (
	"context"
	"errors"
	"fmt"
	"github.com/omecodes/service/connection"
	pb "github.com/omecodes/service/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func (box *Box) ServiceAddress(name string) (string, error) {
	box.serverMutex.Lock()
	defer box.serverMutex.Unlock()

	s, exists := box.services[name]
	if !exists {
		return "", errors.New("not found")
	}
	return s.Address, nil
}

func GRPCConnectionDialer(ctx context.Context, serviceType pb.Type, opts ...grpc.DialOption) (connection.Dialer, error) {
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
		for _, node := range info.Nodes {
			if node.Protocol == pb.Protocol_Grpc {
				tlsConf := ClientTLSConfig(ctx)
				if tlsConf == nil {
					return connection.NewDialer(node.Address, opts...), nil
				} else {
					opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)))
					return connection.NewDialer(node.Address, opts...), nil
				}
			}
		}
	}
	return nil, fmt.Errorf("no service of type %s that supports gRPC has been found", serviceType)
}

func SpecificServiceConnectionDialer(ctx context.Context, serviceID string, opts ...grpc.DialOption) (connection.Dialer, error) {
	reg := Registry(ctx)
	if reg == nil {
		return nil, errors.New("no registry configured")
	}

	info, err := reg.GetService(serviceID)
	if err != nil {
		return nil, err
	}

	for _, node := range info.Nodes {
		tlsConf := ClientTLSConfig(ctx)
		if tlsConf == nil {
			return connection.NewDialer(node.Address, opts...), nil
		} else {
			opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)))
			return connection.NewDialer(node.Address, opts...), nil
		}
	}

	return nil, fmt.Errorf("no service of name %s that supports gRPC has been found", serviceID)
}

func SpecificServiceNodeConnectionDialer(ctx context.Context, serviceID string, nodeName string, opts ...grpc.DialOption) (connection.Dialer, error) {
	reg := Registry(ctx)
	if reg == nil {
		return nil, errors.New("no registry configured")
	}

	info, err := reg.GetService(serviceID)
	if err != nil {
		return nil, err
	}

	for _, node := range info.Nodes {
		if nodeName == node.Name {
			tlsConf := ClientTLSConfig(ctx)
			if tlsConf == nil {
				return connection.NewDialer(node.Address, opts...), nil
			} else {
				opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)))
				return connection.NewDialer(node.Address, opts...), nil
			}
		}
	}

	return nil, fmt.Errorf("no node named %s of service named %s that supports gRPC has been found", nodeName, serviceID)
}

func Connect(ctx context.Context, ofType pb.Type, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	dialer, err := GRPCConnectionDialer(ctx, ofType, opts...)
	if err != nil {
		return nil, err
	}
	return dialer.Dial()
}

func ConnectToSpecificService(ctx context.Context, serviceID string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	dialer, err := SpecificServiceConnectionDialer(ctx, serviceID, opts...)
	if err != nil {
		return nil, err
	}
	return dialer.Dial()
}

func ConnectToSpecificServiceNode(ctx context.Context, serviceID, nodeName string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	dialer, err := SpecificServiceNodeConnectionDialer(ctx, serviceID, nodeName, opts...)
	if err != nil {
		return nil, err
	}
	return dialer.Dial()
}

func (box *Box) GRPCConnectionDialer(serviceType pb.Type, opts ...grpc.DialOption) (connection.Dialer, error) {
	reg := box.Registry()
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
		for _, node := range info.Nodes {
			if node.Protocol == pb.Protocol_Grpc {
				tlsConf := box.ClientMutualTLS()
				if tlsConf == nil {
					return connection.NewDialer(node.Address, opts...), nil
				} else {
					opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)))
					return connection.NewDialer(node.Address, opts...), nil
				}
			}
		}
	}
	return nil, fmt.Errorf("no service of type %s that supports gRPC has been found", serviceType)
}

func (box *Box) SpecificServiceConnectionDialer(serviceID string, opts ...grpc.DialOption) (connection.Dialer, error) {
	reg := box.Registry()
	if reg == nil {
		return nil, errors.New("no registry configured")
	}

	info, err := reg.GetService(serviceID)
	if err != nil {
		return nil, err
	}

	for _, node := range info.Nodes {
		tlsConf := box.ClientMutualTLS()
		if tlsConf == nil {
			return connection.NewDialer(node.Address, opts...), nil
		} else {
			opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)))
			return connection.NewDialer(node.Address, opts...), nil
		}
	}

	return nil, fmt.Errorf("no service of name %s that supports gRPC has been found", serviceID)
}

func (box *Box) SpecificServiceNodeConnectionDialer(serviceID string, nodeName string, opts ...grpc.DialOption) (connection.Dialer, error) {
	reg := box.Registry()
	if reg == nil {
		return nil, errors.New("no registry configured")
	}

	info, err := reg.GetService(serviceID)
	if err != nil {
		return nil, err
	}

	for _, node := range info.Nodes {
		if nodeName == node.Name {
			tlsConf := box.ClientMutualTLS()
			if tlsConf == nil {
				return connection.NewDialer(node.Address, opts...), nil
			} else {
				opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)))
				return connection.NewDialer(node.Address, opts...), nil
			}
		}
	}

	return nil, fmt.Errorf("no node named %s of service named %s that supports gRPC has been found", nodeName, serviceID)
}

func (box *Box) Connect(ofType pb.Type, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	dialer, err := box.GRPCConnectionDialer(ofType, opts...)
	if err != nil {
		return nil, err
	}
	return dialer.Dial()
}

func (box *Box) ConnectToSpecificService(serviceID string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	dialer, err := box.SpecificServiceConnectionDialer(serviceID, opts...)
	if err != nil {
		return nil, err
	}
	return dialer.Dial()
}

func (box *Box) ConnectToSpecificServiceNode(serviceID, nodeName string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	dialer, err := box.SpecificServiceNodeConnectionDialer(serviceID, nodeName, opts...)
	if err != nil {
		return nil, err
	}
	return dialer.Dial()
}
