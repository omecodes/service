package interceptors

import (
	"context"
	"google.golang.org/grpc"
)

type defaultInterceptor struct {
	interceptors []Interceptor
}

func (interceptor *defaultInterceptor) InterceptUnary(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	var err error

	for _, i := range interceptor.interceptors {
		ctx, err = i.Intercept(ctx)
		if err != nil {
			return nil, err
		}
	}

	rsp, err := handler(ctx, req)
	return rsp, err
}

func (interceptor *defaultInterceptor) InterceptStream(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	var err error
	ctx := ss.Context()

	for _, i := range interceptor.interceptors {
		ctx, err = i.Intercept(ctx)
	}

	ss = wrapServerStream(ctx, ss)

	err = handler(srv, ss)
	return err
}

func Default(i ...Interceptor) *defaultInterceptor {
	return &defaultInterceptor{interceptors: i}
}
