package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/omecodes/libome"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func (box *Box) ServiceAddress(name string) (string, error) {
	box.serverMutex.Lock()
	defer box.serverMutex.Unlock()

	s, exists := box.gRPCNodes[name]
	if !exists {
		return "", errors.New("not found")
	}
	return s.Address, nil
}

func GRPCConnectionDialer(ctx context.Context, serviceType uint32, opts ...grpc.DialOption) (Dialer, error) {
	reg := GetRegistry(ctx)
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
			if node.Protocol == ome.Protocol_Grpc {
				tlsConf := GetClientTLSConfig(ctx)
				if tlsConf == nil {
					return NewDialer(node.Address, opts...), nil
				} else {
					opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)))
					return NewDialer(node.Address, opts...), nil
				}
			}
		}
	}
	return nil, fmt.Errorf("no service of type %s that supports gRPC has been found", serviceType)
}

func SpecificServiceConnectionDialer(ctx context.Context, serviceID string, opts ...grpc.DialOption) (Dialer, error) {
	reg := GetRegistry(ctx)
	if reg == nil {
		return nil, errors.New("no registry configured")
	}

	info, err := reg.GetService(serviceID)
	if err != nil {
		return nil, err
	}

	for _, node := range info.Nodes {
		tlsConf := GetClientTLSConfig(ctx)
		if tlsConf == nil {
			return NewDialer(node.Address, opts...), nil
		} else {
			opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)))
			return NewDialer(node.Address, opts...), nil
		}
	}

	return nil, fmt.Errorf("no service of name %s that supports gRPC has been found", serviceID)
}

func SpecificServiceNodeConnectionDialer(ctx context.Context, serviceID string, nodeName string, opts ...grpc.DialOption) (Dialer, error) {
	reg := GetRegistry(ctx)
	if reg == nil {
		return nil, errors.New("no registry configured")
	}

	info, err := reg.GetService(serviceID)
	if err != nil {
		return nil, err
	}

	for _, node := range info.Nodes {
		if nodeName == node.Id {
			tlsConf := GetClientTLSConfig(ctx)
			if tlsConf == nil {
				return NewDialer(node.Address, opts...), nil
			} else {
				opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)))
				return NewDialer(node.Address, opts...), nil
			}
		}
	}

	return nil, fmt.Errorf("no gPRCNode named %s of service named %s that supports gRPC has been found", nodeName, serviceID)
}

func Connect(ctx context.Context, ofType uint32, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
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

func (box *Box) GRPCConnectionDialer(serviceType uint32, opts ...grpc.DialOption) (Dialer, error) {
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
			if node.Protocol == ome.Protocol_Grpc {
				tlsConf := box.ClientMutualTLS()
				if tlsConf == nil {
					return NewDialer(node.Address, opts...), nil
				} else {
					opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)))
					return NewDialer(node.Address, opts...), nil
				}
			}
		}
	}
	return nil, fmt.Errorf("no service of type %s that supports gRPC has been found", serviceType)
}

func (box *Box) SpecificServiceConnectionDialer(serviceID string, opts ...grpc.DialOption) (Dialer, error) {
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
			return NewDialer(node.Address, opts...), nil
		} else {
			opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)))
			return NewDialer(node.Address, opts...), nil
		}
	}

	return nil, fmt.Errorf("no service of name %s that supports gRPC has been found", serviceID)
}

func (box *Box) SpecificServiceNodeConnectionDialer(serviceID string, nodeName string, opts ...grpc.DialOption) (Dialer, error) {
	reg := box.Registry()
	if reg == nil {
		return nil, errors.New("no registry configured")
	}

	info, err := reg.GetService(serviceID)
	if err != nil {
		return nil, err
	}

	for _, node := range info.Nodes {
		if nodeName == node.Id {
			tlsConf := box.ClientMutualTLS()
			if tlsConf == nil {
				return NewDialer(node.Address, opts...), nil
			} else {
				opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)))
				return NewDialer(node.Address, opts...), nil
			}
		}
	}

	return nil, fmt.Errorf("no gPRCNode named %s of service named %s that supports gRPC has been found", nodeName, serviceID)
}

func (box *Box) Connect(ofType uint32, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
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
