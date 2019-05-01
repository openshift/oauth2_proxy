package extensions

//New is a callback to allow extensions to register with the proxy
func New(openshiftCAs []string) []RequestHandler {
	return []RequestHandler{}
}
