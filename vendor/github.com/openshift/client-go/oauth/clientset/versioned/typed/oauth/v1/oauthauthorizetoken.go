// Code generated by client-gen. DO NOT EDIT.

package v1

import (
	"time"

	v1 "github.com/openshift/api/oauth/v1"
	scheme "github.com/openshift/client-go/oauth/clientset/versioned/scheme"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// OAuthAuthorizeTokensGetter has a method to return a OAuthAuthorizeTokenInterface.
// A group's client should implement this interface.
type OAuthAuthorizeTokensGetter interface {
	OAuthAuthorizeTokens() OAuthAuthorizeTokenInterface
}

// OAuthAuthorizeTokenInterface has methods to work with OAuthAuthorizeToken resources.
type OAuthAuthorizeTokenInterface interface {
	Create(*v1.OAuthAuthorizeToken) (*v1.OAuthAuthorizeToken, error)
	Update(*v1.OAuthAuthorizeToken) (*v1.OAuthAuthorizeToken, error)
	Delete(name string, options *metav1.DeleteOptions) error
	DeleteCollection(options *metav1.DeleteOptions, listOptions metav1.ListOptions) error
	Get(name string, options metav1.GetOptions) (*v1.OAuthAuthorizeToken, error)
	List(opts metav1.ListOptions) (*v1.OAuthAuthorizeTokenList, error)
	Watch(opts metav1.ListOptions) (watch.Interface, error)
	Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1.OAuthAuthorizeToken, err error)
	OAuthAuthorizeTokenExpansion
}

// oAuthAuthorizeTokens implements OAuthAuthorizeTokenInterface
type oAuthAuthorizeTokens struct {
	client rest.Interface
}

// newOAuthAuthorizeTokens returns a OAuthAuthorizeTokens
func newOAuthAuthorizeTokens(c *OauthV1Client) *oAuthAuthorizeTokens {
	return &oAuthAuthorizeTokens{
		client: c.RESTClient(),
	}
}

// Get takes name of the oAuthAuthorizeToken, and returns the corresponding oAuthAuthorizeToken object, and an error if there is any.
func (c *oAuthAuthorizeTokens) Get(name string, options metav1.GetOptions) (result *v1.OAuthAuthorizeToken, err error) {
	result = &v1.OAuthAuthorizeToken{}
	err = c.client.Get().
		Resource("oauthauthorizetokens").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do().
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of OAuthAuthorizeTokens that match those selectors.
func (c *oAuthAuthorizeTokens) List(opts metav1.ListOptions) (result *v1.OAuthAuthorizeTokenList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1.OAuthAuthorizeTokenList{}
	err = c.client.Get().
		Resource("oauthauthorizetokens").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do().
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested oAuthAuthorizeTokens.
func (c *oAuthAuthorizeTokens) Watch(opts metav1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Resource("oauthauthorizetokens").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch()
}

// Create takes the representation of a oAuthAuthorizeToken and creates it.  Returns the server's representation of the oAuthAuthorizeToken, and an error, if there is any.
func (c *oAuthAuthorizeTokens) Create(oAuthAuthorizeToken *v1.OAuthAuthorizeToken) (result *v1.OAuthAuthorizeToken, err error) {
	result = &v1.OAuthAuthorizeToken{}
	err = c.client.Post().
		Resource("oauthauthorizetokens").
		Body(oAuthAuthorizeToken).
		Do().
		Into(result)
	return
}

// Update takes the representation of a oAuthAuthorizeToken and updates it. Returns the server's representation of the oAuthAuthorizeToken, and an error, if there is any.
func (c *oAuthAuthorizeTokens) Update(oAuthAuthorizeToken *v1.OAuthAuthorizeToken) (result *v1.OAuthAuthorizeToken, err error) {
	result = &v1.OAuthAuthorizeToken{}
	err = c.client.Put().
		Resource("oauthauthorizetokens").
		Name(oAuthAuthorizeToken.Name).
		Body(oAuthAuthorizeToken).
		Do().
		Into(result)
	return
}

// Delete takes name of the oAuthAuthorizeToken and deletes it. Returns an error if one occurs.
func (c *oAuthAuthorizeTokens) Delete(name string, options *metav1.DeleteOptions) error {
	return c.client.Delete().
		Resource("oauthauthorizetokens").
		Name(name).
		Body(options).
		Do().
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *oAuthAuthorizeTokens) DeleteCollection(options *metav1.DeleteOptions, listOptions metav1.ListOptions) error {
	var timeout time.Duration
	if listOptions.TimeoutSeconds != nil {
		timeout = time.Duration(*listOptions.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Resource("oauthauthorizetokens").
		VersionedParams(&listOptions, scheme.ParameterCodec).
		Timeout(timeout).
		Body(options).
		Do().
		Error()
}

// Patch applies the patch and returns the patched oAuthAuthorizeToken.
func (c *oAuthAuthorizeTokens) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1.OAuthAuthorizeToken, err error) {
	result = &v1.OAuthAuthorizeToken{}
	err = c.client.Patch(pt).
		Resource("oauthauthorizetokens").
		SubResource(subresources...).
		Name(name).
		Body(data).
		Do().
		Into(result)
	return
}
