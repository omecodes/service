package gateway

import (
	"github.com/gorilla/mux"
)

// Router
type Gateway interface {
	Router() (*mux.Router, error)
}
