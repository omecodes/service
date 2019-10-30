package interceptors

import "context"

type WrapContextFunc func(context.Context) (context.Context, error)
