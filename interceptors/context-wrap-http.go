package interceptors

import (
	"net/http"
)

type contextWrapperHandler struct {
	wrapFunc WrapContextFunc
}

func (cw *contextWrapperHandler) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		newContext, err := cw.wrapFunc(ctx)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		r = r.WithContext(newContext)
		next(w, r)
	}
}

func NewHttpHandlerContextWrapper(wrapFunc WrapContextFunc) *contextWrapperHandler {
	return &contextWrapperHandler{wrapFunc: wrapFunc}
}
