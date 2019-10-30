package interceptors

import "context"

type contextWrapper struct {
	wrapperFunc WrapContextFunc
}

func (c *contextWrapper) Name() string {
	return CtxWrap
}

func (c *contextWrapper) Validate(ctx context.Context) (context.Context, error) {
	return c.wrapperFunc(ctx)
}

func NewContextWrapper(wrapperFunc WrapContextFunc) *contextWrapper {
	return &contextWrapper{wrapperFunc: wrapperFunc}
}
