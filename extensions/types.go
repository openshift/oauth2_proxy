package extensions

import (
	"net/http"
)

//FnHandlerRequest is a function that can process a request
type FnHandlerRequest func(req *http.Request, context interface{}) (*http.Request, error)

//RequestHandler if a function that modifies a request.  Execution occurs
//after authentication but before proxy to upstream
type RequestHandler interface {
	//Process the request and return the modification or error
	Process(req *http.Request, context interface{}) (*http.Request, error)
	//Name of the request handler
	Name() string
}

//SimpleRequestHandler is a simple container to modify requests
type SimpleRequestHandler struct {
	name      string
	processor FnHandlerRequest
}

//Name of the requesthandler
func (h *SimpleRequestHandler) Name() string {
	return h.name
}

//Process the Request
func (h *SimpleRequestHandler) Process(req *http.Request, context interface{}) (*http.Request, error) {
	return h.processor(req, context)
}

//NewRequestHandler creates a named wrapper to a requesthandler function
func NewRequestHandler(name string, handler FnHandlerRequest) *SimpleRequestHandler {
	return &SimpleRequestHandler{
		name,
		handler,
	}
}
