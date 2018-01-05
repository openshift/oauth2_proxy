package openshift

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/bitly/go-simplejson"
	"github.com/openshift/oauth-proxy/providers"
	"github.com/openshift/oauth-proxy/util"

	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	authenticationv1beta1 "k8s.io/client-go/pkg/apis/authentication/v1beta1"
	authorizationv1beta1 "k8s.io/client-go/pkg/apis/authorization/v1beta1"
)

func emptyURL(u *url.URL) bool {
	return u == nil || u.String() == ""
}

type OpenShiftProvider struct {
	*providers.ProviderData

	ReviewURL *url.URL
	Client    *http.Client

	AuthenticationOptions DelegatingAuthenticationOptions
	AuthorizationOptions  DelegatingAuthorizationOptions

	authenticator authenticator.Request
	authorizer    authorizer.Authorizer
	defaultRecord authorizer.AttributesRecord
	reviews       []string
	paths         recordsByPath

	ProjectURL *url.URL
}

func New() *OpenShiftProvider {
	p := &OpenShiftProvider{}
	p.AuthenticationOptions.SkipInClusterLookup = true
	p.AuthenticationOptions.CacheTTL = 2 * time.Minute
	p.AuthorizationOptions.AllowCacheTTL = 2 * time.Minute
	p.AuthorizationOptions.DenyCacheTTL = 5 * time.Second
	return p
}

func (p *OpenShiftProvider) Bind(flags *flag.FlagSet) {
	p.AuthenticationOptions.AddFlags(flags)
	p.AuthorizationOptions.AddFlags(flags)
}

// LoadDefaults accepts configuration and loads defaults from the environment, or returns an error.
// The provider may partially initialize config for subsequent calls.
func (p *OpenShiftProvider) LoadDefaults(serviceAccount string, caPaths []string, reviewJSON, resources string, extraData bool) (*providers.ProviderData, error) {
	if len(resources) > 0 {
		paths, err := parseResources(resources)
		if err != nil {
			return nil, err
		}
		p.paths = paths
	}
	reviews, err := parseSubjectAccessReviews(reviewJSON)
	if err != nil {
		return nil, err
	}
	p.reviews = reviews

	if err := p.setCA(caPaths); err != nil {
		return nil, err
	}

	var scope string
	scope = "user:info user:check-access"
	if extraData == true {
		scope = scope + " user:list-projects"
	}

	defaults := &providers.ProviderData{
		Scope: scope,
	}

	// all OpenShift service accounts are OAuth clients, use this if we have it
	if len(serviceAccount) > 0 {
		if data, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil && len(data) > 0 {
			defaults.ClientID = fmt.Sprintf("system:serviceaccount:%s:%s", strings.TrimSpace(string(data)), serviceAccount)
			log.Printf("Defaulting client-id to %s", defaults.ClientID)
		}
		tokenPath := "/var/run/secrets/kubernetes.io/serviceaccount/token"
		if data, err := ioutil.ReadFile(tokenPath); err == nil && len(data) > 0 {
			defaults.ClientSecret = strings.TrimSpace(string(data))
			log.Printf("Defaulting client-secret to service account token %s", tokenPath)
		}
	}

	// attempt to discover endpoints
	if err := discoverOpenShiftOAuth(defaults, p.Client); err != nil {
		log.Printf("Unable to discover default cluster OAuth info: %v", err)
		return defaults, nil
	}
	// provide default URLs
	if !emptyURL(defaults.LoginURL) {
		defaults.ValidateURL = &url.URL{
			Scheme: defaults.LoginURL.Scheme,
			Host:   defaults.LoginURL.Host,
			Path:   "/apis/user.openshift.io/v1/users/~",
		}
	}
	return defaults, nil
}

// SetCA initializes the client used for connecting to the master.
func (p *OpenShiftProvider) setCA(paths []string) error {
	if p.Client == nil {
		p.Client = &http.Client{
			Jar:       http.DefaultClient.Jar,
			Transport: http.DefaultTransport,
		}
	}
	//defaults
	capaths := []string{"/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"}
	system_roots := true
	if len(paths) != 0 {
		capaths = paths
		system_roots = false
	}
	pool, err := util.GetCertPool(capaths, system_roots)
	if err != nil {
		return err
	}
	p.Client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: pool,
		},
	}
	return nil
}

// encodeSARWithScope adds a "scopes" array to the SAR if it does not have one already, and outputs
// encoded bytes.
func encodeSARWithScope(json *simplejson.Json) ([]byte, error) {
	if len(json.Get("scopes").MustArray()) == 0 {
		json.Set("scopes", []interface{}{})
	}
	return json.Encode()
}

// parseSubjectAccessReviews parses a list of SAR records and ensures they are properly scoped.
func parseSubjectAccessReviews(review string) ([]string, error) {
	review = strings.TrimSpace(review)
	if len(review) == 0 {
		return nil, nil
	}

	// Convert to a json array to simplify encoding later
	if review[0] != '[' && review[len(review)-1] != ']' {
		review = "[" + review + "]"
	}

	json, err := simplejson.NewJson([]byte(review))
	if err != nil {
		return nil, fmt.Errorf("unable to decode review: %v", err)
	}

	var reviews []string
	for i := range json.MustArray() {
		data, err := encodeSARWithScope(json.GetIndex(i))
		if err != nil {
			return nil, fmt.Errorf("unable to encode modified review: %v (%#v)", err, json)
		}
		reviews = append(reviews, string(data))
	}
	return reviews, nil
}

type pathRecord struct {
	path   string
	record authorizer.AttributesRecord
}

type recordsByPath []pathRecord

func (o recordsByPath) Len() int      { return len(o) }
func (o recordsByPath) Swap(i, j int) { o[i], o[j] = o[j], o[i] }
func (o recordsByPath) Less(i, j int) bool {
	// match longest paths first
	if len(o[j].path) < len(o[i].path) {
		return true
	}
	// match in lexographic order otherwise
	return o[i].path < o[j].path
}

func (o recordsByPath) Match(path string) (pathRecord, bool) {
	for i := range o {
		if strings.HasPrefix(path, o[i].path) {
			return o[i], true
		}
	}
	return pathRecord{}, false
}

// parseResources creates a map of path prefixes (the keys in the provided input) to
// SubjectAccessReview ResourceAttributes (the keys) and returns the records ordered
// by longest path first, or an error.
func parseResources(resources string) (recordsByPath, error) {
	defaults := authorizer.AttributesRecord{
		Verb:            "proxy",
		ResourceRequest: true,
	}
	var paths recordsByPath
	mappings := make(map[string]authorizationv1beta1.ResourceAttributes)
	if err := json.Unmarshal([]byte(resources), &mappings); err != nil {
		return nil, fmt.Errorf("resources must be a JSON map of paths to authorizationv1beta1.ResourceAttributes: %v", err)
	}
	for path, attrs := range mappings {
		r := defaults
		if len(attrs.Verb) > 0 {
			r.Verb = attrs.Verb
		}
		if len(attrs.Group) > 0 {
			r.APIGroup = attrs.Group
		}
		if len(attrs.Version) > 0 {
			r.APIVersion = attrs.Version
		}
		if len(attrs.Resource) > 0 {
			r.Resource = attrs.Resource
		}
		if len(attrs.Subresource) > 0 {
			r.Subresource = attrs.Subresource
		}
		if len(attrs.Namespace) > 0 {
			r.Namespace = attrs.Namespace
		}
		if len(attrs.Name) > 0 {
			r.Name = attrs.Name
		}
		paths = append(paths, pathRecord{
			path:   path,
			record: r,
		})
	}
	sort.Sort(paths)
	return paths, nil
}

// Complete performs final setup on the provider or returns an error.
func (p *OpenShiftProvider) Complete(data *providers.ProviderData, reviewURL *url.URL) error {
	if emptyURL(reviewURL) {
		if emptyURL(data.LoginURL) {
			return fmt.Errorf("--openshift-review-url must be specified")
		}
		reviewURL = &url.URL{
			Scheme: data.LoginURL.Scheme,
			Host:   data.LoginURL.Host,
			Path:   "/apis/authorization.openshift.io/v1/subjectaccessreviews",
		}
	}

	p.ProjectURL = &url.URL{
		Scheme: data.ValidateURL.Scheme,
		Host:   data.ValidateURL.Host,
		Path:   "/apis/project.openshift.io/v1/projects",
	}

	p.ProviderData = data
	p.ReviewURL = reviewURL

	if len(p.paths) > 0 {
		log.Printf("Delegation of authentication and authorization to OpenShift is enabled for bearer tokens and client certificates.")

		authenticator, err := p.AuthenticationOptions.ToAuthenticationConfig()
		if err != nil {
			return fmt.Errorf("unable to configure authenticator: %v", err)
		}
		// check whether we have access to perform authentication review
		if authenticator.TokenAccessReviewClient != nil {
			_, err := authenticator.TokenAccessReviewClient.Create(&authenticationv1beta1.TokenReview{
				Spec: authenticationv1beta1.TokenReviewSpec{
					Token: "TEST",
				},
			})
			if err != nil {
				return fmt.Errorf("unable to retrieve authentication information for tokens: %v", err)
			}
		}

		authorizer, err := p.AuthorizationOptions.ToAuthorizationConfig()
		if err != nil {
			return fmt.Errorf("unable to configure authorizer: %v", err)
		}
		// check whether we have access to perform authentication review
		if authorizer.SubjectAccessReviewClient != nil {
			_, err := authorizer.SubjectAccessReviewClient.Create(&authorizationv1beta1.SubjectAccessReview{
				Spec: authorizationv1beta1.SubjectAccessReviewSpec{
					User: "TEST",
					ResourceAttributes: &authorizationv1beta1.ResourceAttributes{
						Resource: "TEST",
						Verb:     "TEST",
					},
				},
			})
			if err != nil {
				return fmt.Errorf("unable to retrieve authorization information for users: %v", err)
			}
		}

		p.authenticator, _, err = authenticator.New()
		if err != nil {
			return fmt.Errorf("unable to configure authenticator: %v", err)
		}

		p.authorizer, err = authorizer.New()
		if err != nil {
			return fmt.Errorf("unable to configure authorizer: %v", err)
		}
	}
	return nil
}

func (p *OpenShiftProvider) ValidateRequest(req *http.Request) (*providers.SessionState, error) {
	// no authenticator is registered
	if p.authenticator == nil {
		return nil, nil
	}

	// find a match
	record, ok := p.paths.Match(req.URL.Path)
	if !ok {
		log.Printf("no resource mapped path")
		return nil, nil
	}

	// authenticate
	user, ok, err := p.authenticator.AuthenticateRequest(req)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}

	// authorize
	record.record.User = user
	ok, reason, err := p.authorizer.Authorize(record.record)
	if err != nil {
		return nil, err
	}
	if !ok {
		log.Printf("authorizer reason: %s", reason)
		return nil, nil
	}
	return &providers.SessionState{User: user.GetName(), Email: user.GetName() + "@cluster.local"}, nil
}

func (p *OpenShiftProvider) GetEmailAddress(s *providers.SessionState) (string, error) {
	req, err := http.NewRequest("GET", p.ValidateURL.String(), nil)
	if err != nil {
		log.Printf("failed building request %s", err)
		return "", fmt.Errorf("unable to build request to get user email info: %v", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.AccessToken))
	json, err := request(p.Client, req)
	if err != nil {
		return "", fmt.Errorf("unable to retrieve email address for user from token: %v", err)
	}
	name, err := json.Get("metadata").Get("name").String()
	if err != nil {
		return "", fmt.Errorf("user information has no name field: %v", err)
	}
	if !strings.Contains(name, "@") {
		name = name + "@cluster.local"
	}
	if err := p.reviewUser(name, s.AccessToken); err != nil {
		return "", err
	}
	return name, nil
}

func (p *OpenShiftProvider) reviewUser(name, accessToken string) error {
	for _, review := range p.reviews {
		req, err := http.NewRequest("POST", p.ReviewURL.String(), bytes.NewBufferString(review))
		if err != nil {
			log.Printf("failed building request %s", err)
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
		json, err := request(p.Client, req)
		if err != nil {
			return err
		}
		allowed, err := json.Get("allowed").Bool()
		if err != nil {
			return err
		}
		if !allowed {
			log.Printf("Permission denied for %s for check %s", name, review)
			return providers.ErrPermissionDenied
		}
	}
	return nil
}

func (p *OpenShiftProvider) GetUserProjects(s *providers.SessionState) (projs []string, err error) {
	projs = []string{}
	req, err := http.NewRequest("GET", p.ProjectURL.String(), nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.AccessToken))
	json, err := request(p.Client, req)
	if err != nil {
		return
	}
	projects, err := json.Get("items").Array()
	if err != nil {
		return
	}

	for _, i := range projects {
		project, ok := i.(map[string]interface{})
		if !ok {
			err = errors.New(fmt.Sprintf("invalid project data: %s", err))
			return
		}
		metadata, ok := project["metadata"].(map[string]interface{})
		if !ok {
			err = errors.New(fmt.Sprintf("bad project metadata: %s", err))
			return
		}
		projs = append(projs, metadata["name"].(string))
	}
	log.Printf("project list %s", projs)
	return
}

func (p *OpenShiftProvider) GetExtraData(s *providers.SessionState) (d map[string]string, err error) {
	d = map[string]string{}
	projects, err := p.GetUserProjects(s)
	if err != nil {
		return
	}
	d["Projects"] = fmt.Sprint(strings.Join(projects, ","))
	return
}

// Copied up only to set a different client CA
func (p *OpenShiftProvider) Redeem(redirectURL, code string) (s *providers.SessionState, err error) {
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
		s = &providers.SessionState{
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
		s = &providers.SessionState{AccessToken: a}
	} else {
		err = fmt.Errorf("no access token found %s", body)
	}
	return
}

func discoverOpenShiftOAuth(provider *providers.ProviderData, client *http.Client) error {
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
	json, err := request(client, req)
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
