package connection

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
)

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
