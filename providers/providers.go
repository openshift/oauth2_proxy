package providers

import (
	"errors"
	"net/http"

	"github.com/openshift/oauth-proxy/cookie"
)

type Provider interface {
	Data() *ProviderData

	GetEmailAddress(*SessionState) (string, error)
	GetExtraData(*SessionState) (map[string]string, error)
	Redeem(string, string) (*SessionState, error)
	ValidateGroup(string) bool
	ValidateSessionState(*SessionState) bool
	GetLoginURL(redirectURI, finalRedirect string) string
	RefreshSessionIfNeeded(*SessionState) (bool, error)
	SessionFromCookie(string, *cookie.Cipher) (*SessionState, error)
	CookieForSession(*SessionState, *cookie.Cipher) (string, error)
	ValidateRequest(*http.Request) (*SessionState, error)
}

// ErrPermissionDenied may be returned from Redeem() to indicate the user is not allowed to login.
var ErrPermissionDenied = errors.New("permission denied")
