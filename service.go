package service

import (
	"context"
	"github.com/omecodes/errors"

	"github.com/omecodes/libome"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func (box *Box) ServiceAddress(name string) (string, error) {
	box.serverMutex.Lock()
	defer box.serverMutex.Unlock()

	s, exists := box.gRPCNodes[name]
	if !exists {
		return "", errors.NotFound("service info not found", errors.Details{Key: "type", Value: "service"}, errors.Details{Key: "name", Value: name})
	}
	return s.Address, nil
}

func GRPCConnectionDialer(ctx context.Context, serviceType uint32, opts ...grpc.DialOption) (Dialer, error) {
	reg := GetRegistry(ctx)
	if reg == nil {
		return nil, errors.Internal("no registry")
	}

	infos, err := reg.GetOfType(serviceType)
	if err != nil {
		return nil, err
	}

	if len(infos) == 0 {
		return nil, errors.ServiceUnavailable("not service found", errors.Details{Key: "type", Value: "service-type"}, errors.Details{Key: "code", Value: serviceType})
	}

	for _, info := range infos {
		for _, node := range info.Nodes {
			if node.Protocol == ome.Protocol_Grpc {
				tlsConf, err := GetClientTLSConfig(ctx)
				if err != nil {
					return nil, err
				}
				opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)))
				return NewDialer(node.Address, opts...), nil

			}
		}
	}
	return nil, errors.NotFound("service not found")
}

func SpecificServiceConnectionDialer(ctx context.Context, serviceID string, opts ...grpc.DialOption) (Dialer, error) {
	reg := GetRegistry(ctx)
	if reg == nil {
		return nil, errors.Internal("no registry")
	}

	info, err := reg.GetService(serviceID)
	if err != nil {
		return nil, err
	}

	for _, node := range info.Nodes {
		tlsConf, err := GetClientTLSConfig(ctx)
		if err != nil {
			return nil, err
		}

		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)))
		return NewDialer(node.Address, opts...), nil
	}

	return nil, errors.ServiceUnavailable("not service found", errors.Details{Key: "type", Value: "service-id"}, errors.Details{Key: "id", Value: serviceID})
}

func SpecificServiceNodeConnectionDialer(ctx context.Context, serviceID string, nodeName string, opts ...grpc.DialOption) (Dialer, error) {
	reg := GetRegistry(ctx)
	if reg == nil {
		return nil, errors.Internal("no registry")
	}

	info, err := reg.GetService(serviceID)
	if err != nil {
		return nil, err
	}

	for _, node := range info.Nodes {
		if nodeName == node.Id {
			tlsConf, err := GetClientTLSConfig(ctx)
			if err != nil {
				return nil, err
			}
			opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)))
			return NewDialer(node.Address, opts...), nil
		}
	}

	return nil, errors.ServiceUnavailable("not service found", errors.Details{Key: "type", Value: "service-id"}, errors.Details{Key: "node", Value: nodeName}, errors.Details{Key: "id", Value: serviceID})
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
	reg, err := box.Registry()
	if err != nil {
		return nil, err
	}

	infos, err := reg.GetOfType(serviceType)
	if err != nil {
		return nil, err
	}

	if len(infos) == 0 {
		return nil, errors.ServiceUnavailable("not service found", errors.Details{Key: "type", Value: "service-type"}, errors.Details{Key: "code", Value: serviceType})
	}

	for _, info := range infos {
		for _, node := range info.Nodes {
			if node.Protocol == ome.Protocol_Grpc {
				tlsConf, err := box.ClientMutualTLS()
				if err != nil {
					return nil, err
				}
				opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)))
				return NewDialer(node.Address, opts...), nil
			}
		}
	}
	return nil, errors.ServiceUnavailable("not service found", errors.Details{Key: "type", Value: "service-type"}, errors.Details{Key: "code", Value: serviceType})
}

func (box *Box) SpecificServiceConnectionDialer(serviceID string, opts ...grpc.DialOption) (Dialer, error) {
	reg, err := box.Registry()
	if err != nil {
		return nil, err
	}

	info, err := reg.GetService(serviceID)
	if err != nil {
		return nil, err
	}

	for _, node := range info.Nodes {
		tlsConf, err := box.ClientMutualTLS()
		if err != nil {
			return nil, nil
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)))
		return NewDialer(node.Address, opts...), nil
	}

	return nil, errors.ServiceUnavailable("not service found", errors.Details{Key: "type", Value: "service-id"}, errors.Details{Key: "id", Value: serviceID})
}

func (box *Box) SpecificServiceNodeConnectionDialer(serviceID string, nodeName string, opts ...grpc.DialOption) (Dialer, error) {
	reg, err := box.Registry()
	if err != nil {
		return nil, err
	}

	info, err := reg.GetService(serviceID)
	if err != nil {
		return nil, err
	}

	for _, node := range info.Nodes {
		if nodeName == node.Id {
			tlsConf, err := box.ClientMutualTLS()
			if err != nil {
				return nil, err
			}
			opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)))
			return NewDialer(node.Address, opts...), nil
		}
	}

	return nil, errors.ServiceUnavailable("not service found", errors.Details{Key: "type", Value: "service-id"}, errors.Details{Key: "node", Value: nodeName}, errors.Details{Key: "id", Value: serviceID})
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
