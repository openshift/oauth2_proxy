package providers

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/bitly/go-simplejson"
	"os"
)

func emptyURL(u *url.URL) bool {
	return u == nil || u.String() == ""
}

type OpenShiftProvider struct {
	*ProviderData

	ReviewURL *url.URL
	Client    *http.Client

	requiredGroups []string
	reviews        []string
}

func NewOpenShiftProvider(p *ProviderData) *OpenShiftProvider {
	p.ProviderName = "OpenShift"

	provider := &OpenShiftProvider{ProviderData: p}

	// these scopes are all that are required to verify user access
	if p.Scope == "" {
		p.Scope = "user:info user:check-access"
	}
	return provider
}

func (p *OpenShiftProvider) SetGroupRestriction(group string) {
	if len(group) == 0 {
		return
	}
	var extensions []json.RawMessage
	if err := json.Unmarshal([]byte(group), &extensions); err == nil {
		for _, ext := range extensions {
			p.requiredGroups = append(p.requiredGroups, string(ext))
		}
		return
	}
	p.requiredGroups = []string{group}
}

func (p *OpenShiftProvider) SetSubjectAccessReviews(review string) {
	if len(review) == 0 {
		return
	}
	json, err := simplejson.NewJson([]byte(review))
	if err != nil {
		log.Printf("Unable to decode review: %v", err)
		p.reviews = []string{review}
		return
	}

	if json.MustMap() != nil {
		if len(json.Get("scopes").MustArray()) == 0 {
			json.Set("scopes", []interface{}{})
		}
		data, err := json.EncodePretty()
		if err != nil {
			log.Printf("Unable to encode modified review: %v (%#v)", err, json)
			p.reviews = []string{review}
			return
		}
		p.reviews = []string{string(data)}
		return
	}

	for i := range json.MustArray() {
		if len(json.GetIndex(i).Get("scopes").MustArray()) == 0 {
			json.GetIndex(i).Set("scopes", []interface{}{})
		}
		data, err := json.EncodePretty()
		if err != nil {
			log.Printf("Unable to encode modified review: %v (%#v)", err, json)
			p.reviews = []string{review}
			return
		}
		p.reviews = append(p.reviews, string(data))
	}
}

func (p *OpenShiftProvider) SetCA(paths []string) error {
	if p.Client == nil {
		p.Client = &http.Client{
			Jar:       http.DefaultClient.Jar,
			Transport: http.DefaultTransport,
		}
	}

	pool := x509.NewCertPool()
	for _, path := range paths {
		data, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}
		if !pool.AppendCertsFromPEM(data) {
			return fmt.Errorf("certificate authority file at %s could not be read", path)
		}
	}
	p.Client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: pool,
		},
	}
	return nil
}

func (p *OpenShiftProvider) Configure(groups, reviews string, caPaths []string) error {
	if len(caPaths) == 0 {
		// ignore errors
		p.SetCA([]string{"/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"})
	} else {
		if err := p.SetCA(caPaths); err != nil {
			return err
		}
	}
	p.SetGroupRestriction(groups)
	p.SetSubjectAccessReviews(reviews)

	// attempt to discover endpoints as if we are in cluster
	if emptyURL(p.LoginURL) && emptyURL(p.RedeemURL) {
		if err := discoverOpenShiftOAuth(p); err != nil {
			return fmt.Errorf("discovery failed: %v", err)
		}
	}
	// provide default URLs
	if !emptyURL(p.LoginURL) {
		if emptyURL(p.ValidateURL) {
			p.ValidateURL = &url.URL{
				Scheme: p.LoginURL.Scheme,
				Host:   p.LoginURL.Host,
				Path:   "/apis/user.openshift.io/v1/users/~",
			}
		}
		if emptyURL(p.ReviewURL) {
			p.ReviewURL = &url.URL{
				Scheme: p.LoginURL.Scheme,
				Host:   p.LoginURL.Host,
				Path:   "/apis/authorization.openshift.io/v1/subjectaccessreviews",
			}
		}
	}
	return nil
}

func (p *OpenShiftProvider) GetEmailAddress(s *SessionState) (string, error) {
	req, err := http.NewRequest("GET", p.ValidateURL.String(), nil)
	if err != nil {
		log.Printf("failed building request %s", err)
		return "", err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.AccessToken))
	json, err := request(p.Client, req)
	if err != nil {
		log.Printf("failed making request %s", err)
		return "", err
	}
	name, err := json.Get("metadata").Get("name").String()
	if err != nil {
		return "", err
	}
	if !strings.Contains(name, "@") {
		name = name + "@cluster.local"
	}
	if len(p.requiredGroups) > 0 {
		for _, group := range json.Get("groups").MustStringArray() {
			for _, require := range p.requiredGroups {
				if group == require {
					return name, nil
				}
			}
		}
		log.Printf("Permission denied for %s - not in any of the required groups %v", name, p.requiredGroups)
		return "", ErrPermissionDenied
	}

	for _, review := range p.reviews {
		req, err := http.NewRequest("POST", p.ReviewURL.String(), bytes.NewBufferString(review))
		if err != nil {
			log.Printf("failed building request %s", err)
			return "", err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.AccessToken))
		json, err := request(p.Client, req)
		if err != nil {
			log.Printf("failed making request %s", err)
			return "", err
		}
		allowed, err := json.Get("allowed").Bool()
		if err != nil {
			return "", err
		}
		if !allowed {
			log.Printf("Permission denied for %s for check %s", name, review)
			return "", ErrPermissionDenied
		}
	}

	return name, nil
}

// Copied up only to set a different client CA
func (p *OpenShiftProvider) Redeem(redirectURL, code string) (s *SessionState, err error) {
	if code == "" {
		err = errors.New("missing code")
		return
	}
	client := p.Client
	if client == nil {
		client = http.DefaultClient
	}

	params := url.Values{}
	params.Add("redirect_uri", redirectURL)
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	if p.ProtectedResource != nil && p.ProtectedResource.String() != "" {
		params.Add("resource", p.ProtectedResource.String())
	}

	var req *http.Request
	req, err = http.NewRequest("POST", p.RedeemURL.String(), bytes.NewBufferString(params.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var resp *http.Response
	resp, err = client.Do(req)
	if err != nil {
		return nil, err
	}
	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return
	}

	if resp.StatusCode != 200 {
		err = fmt.Errorf("got %d from %q %s", resp.StatusCode, p.RedeemURL.String(), body)
		return
	}

	// blindly try json and x-www-form-urlencoded
	var jsonResponse struct {
		AccessToken string `json:"access_token"`
	}
	err = json.Unmarshal(body, &jsonResponse)
	if err == nil {
		s = &SessionState{
			AccessToken: jsonResponse.AccessToken,
		}
		return
	}

	var v url.Values
	v, err = url.ParseQuery(string(body))
	if err != nil {
		return
	}
	if a := v.Get("access_token"); a != "" {
		s = &SessionState{AccessToken: a}
	} else {
		err = fmt.Errorf("no access token found %s", body)
	}
	return
}

func discoverOpenShiftOAuth(provider *OpenShiftProvider) error {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	if len(host) == 0 {
		host = "kubernetes.default.svc"
	}
	wellKnownAuthorization := &url.URL{Scheme: "https", Host: host, Path: "/.well-known/oauth-authorization-server"}
	log.Printf("Performing OAuth discovery against %s", wellKnownAuthorization)
	req, err := http.NewRequest("GET", wellKnownAuthorization.String(), nil)
	if err != nil {
		return err
	}
	json, err := request(provider.Client, req)
	if err != nil {
		return err
	}
	if emptyURL(provider.LoginURL) {
		if value, err := json.Get("authorization_endpoint").String(); err == nil && len(value) > 0 {
			if u, err := url.Parse(value); err == nil {
				provider.LoginURL = u
			} else {
				log.Printf("Unable to parse 'authorization_endpoint' from %s: %v", wellKnownAuthorization, err)
			}
		} else {
			log.Printf("No 'authorization_endpoint' provided by %s: %v", wellKnownAuthorization, err)
		}
	}
	if emptyURL(provider.RedeemURL) {
		if value, err := json.Get("token_endpoint").String(); err == nil && len(value) > 0 {
			if u, err := url.Parse(value); err == nil {
				provider.RedeemURL = u
			} else {
				log.Printf("Unable to parse 'token_endpoint' from %s: %v", wellKnownAuthorization, err)
			}
		} else {
			log.Printf("No 'token_endpoint' provided by %s: %v", wellKnownAuthorization, err)
		}
	}
	return nil
}

// Copied to override http.Client so that CA can be set
func request(client *http.Client, req *http.Request) (*simplejson.Json, error) {
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("%s %s %s", req.Method, req.URL, err)
		return nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	log.Printf("%d %s %s %s", resp.StatusCode, req.Method, req.URL, body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("got %d %s", resp.StatusCode, body)
	}
	data, err := simplejson.NewJson(body)
	if err != nil {
		return nil, err
	}
	return data, nil
}
