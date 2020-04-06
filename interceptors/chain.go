package interceptors

import (
	"context"
	"google.golang.org/grpc"
	"log"
	"path"
	"time"
)

type defaultInterceptor struct {
	interceptors []Interceptor
}

func (interceptor *defaultInterceptor) InterceptUnary(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	var err error
	start := time.Now()
	method := path.Base(info.FullMethod)

	for _, i := range interceptor.interceptors {
		ctx, err = i.Intercept(ctx)
	}

	rsp, err := handler(ctx, req)
	log.Printf("gRPC request - Method:%s\tDuration:%s\tError:%v\n", method, time.Since(start), err)
	return rsp, err
}

func (interceptor *defaultInterceptor) InterceptStream(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	var err error
	start := time.Now()
	ctx := ss.Context()
	method := path.Base(info.FullMethod)

	for _, i := range interceptor.interceptors {
		ctx, err = i.Intercept(ctx)
	}

	ss = wrapServerStream(ctx, ss)
	ss = newLoggedStream(ss)

	err = handler(srv, ss)
	log.Printf("gRPC request - Method:%s\tDuration:%s\tError:%v\n", method, time.Since(start), err)
	return err
}

func Default(i ...Interceptor) *defaultInterceptor {
	return &defaultInterceptor{interceptors: i}
}
