package main

import (
	"log"

	"github.com/openshift/oauth-proxy/extensions"
)

func (proxy *OAuthProxy) registerExtensions(openshiftCAs StringArray) {
	log.Printf("Registering Extensions....")

	handlers := extensions.New(openshiftCAs)
	proxy.requestHandlers = append(proxy.requestHandlers, handlers...)
}
