package interceptors

import (
	"github.com/zoenion/common/log"
	"net/http"
	"time"
)

type httpLogger struct {
	name string
}

func (l *httpLogger) Handle(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		duration := time.Since(start)
		log.Info(
			r.Method + " " + r.RequestURI,
			log.Field("params", r.URL.RawQuery),
			log.Field("handler", l.name),
			log.Field("duration", duration.String()),
		)
	})
}

func NewHttpLogger(name string) *httpLogger {
	return &httpLogger{name: name}
}
