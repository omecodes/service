package interceptors

import (
	"log"
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
		log.Printf(
			"%s %s %s %s",
			r.Method,
			r.RequestURI,
			l.name,
			time.Since(start),
		)
	})
}

func NewHttpLogger(name string) *httpLogger {
	return &httpLogger{name: name}
}
