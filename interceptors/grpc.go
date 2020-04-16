package interceptors

import (
	"context"
	"google.golang.org/grpc"
	"log"
	"time"
)

type loggedStream struct {
	grpc.ServerStream
}

func (w *loggedStream) RecvMsg(m interface{}) error {
	log.Printf("Receive a message (Type: %v) at %s\n", m, time.Now().Format(time.RFC3339))
	return w.ServerStream.RecvMsg(m)
}

func (w *loggedStream) SendMsg(m interface{}) error {
	log.Printf("Send a message (Type: %v) at %v\n", m, time.Now().Format(time.RFC3339))
	return w.ServerStream.SendMsg(m)
}

func newLoggedStream(s grpc.ServerStream) grpc.ServerStream {
	return &loggedStream{s}
}

type GRPC interface {
	InterceptUnary(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error)
	InterceptStream(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error
}
