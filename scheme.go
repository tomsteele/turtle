package turtle

import "net/http"

// Scheme is an abstraction layer around a session management and authentication
// scheme. Authenticate should authenticate a request and return credentials or an error.
// Any presence of an error will indicate an authentication failure.
type Scheme interface {
	Authenticate(w http.ResponseWriter, r *http.Request) (interface{}, error)
}
