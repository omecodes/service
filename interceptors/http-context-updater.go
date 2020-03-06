package interceptors

import (
	"context"
	"net/http"
)

type contextUpdater struct {
	updaterFunc func(ctx context.Context) context.Context
}

func (atv *contextUpdater) Handle(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := atv.updaterFunc(r.Context())
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

func NewContextUpdater(updaterFunc func(ctx context.Context) context.Context) *contextUpdater {
	return &contextUpdater{updaterFunc: updaterFunc}
}
