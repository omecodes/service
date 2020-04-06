package interceptors

import (
	"context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func wrapServerStream(ctx context.Context, ss grpc.ServerStream) grpc.ServerStream {
	return &gRPCServerStreamContextWrapper{
		wrapped: ss,
		ctx:     ctx,
	}
}

type gRPCServerStreamContextWrapper struct {
	wrapped grpc.ServerStream
	ctx     context.Context
}

func (g *gRPCServerStreamContextWrapper) SetHeader(m metadata.MD) error {
	return g.wrapped.SetHeader(m)
}

func (g *gRPCServerStreamContextWrapper) SendHeader(m metadata.MD) error {
	return g.wrapped.SendHeader(m)
}

func (g *gRPCServerStreamContextWrapper) SetTrailer(m metadata.MD) {
	g.wrapped.SetTrailer(m)
}

func (g *gRPCServerStreamContextWrapper) Context() context.Context {
	if g.ctx == nil {
		return g.wrapped.Context()
	}
	return g.ctx
}

func (g *gRPCServerStreamContextWrapper) SendMsg(m interface{}) error {
	return g.wrapped.SendMsg(m)
}

func (g *gRPCServerStreamContextWrapper) RecvMsg(m interface{}) error {
	return g.wrapped.RecvMsg(m)
}
