package e2e

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	mathrand "math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/net/html"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"

	oscrypto "github.com/openshift/library-go/pkg/crypto"
)

const (
	// How often to poll for conditions
	Poll = 2 * time.Second
	// Default time to wait for operations to complete
	defaultTimeout = 30 * time.Second
)

func restClientConfig(config, context string) (*api.Config, error) {
	if config == "" {
		return nil, fmt.Errorf("Config file must be specified to load client config")
	}
	c, err := clientcmd.LoadFromFile(config)
	if err != nil {
		return nil, fmt.Errorf("error loading config: %v", err.Error())
	}
	if context != "" {
		c.CurrentContext = context
	}
	return c, nil
}

func loadConfig(config, context string) (*rest.Config, error) {
	c, err := restClientConfig(config, context)
	if err != nil {
		return nil, err
	}
	return clientcmd.NewDefaultClientConfig(*c, &clientcmd.ConfigOverrides{}).ClientConfig()
}

// Waits default amount of time (PodStartTimeout) for the specified pod to become running.
// Returns an error if timeout occurs first, or pod goes in to failed state.
func waitForPodRunningInNamespace(c kubernetes.Interface, pod *corev1.Pod) error {
	if pod.Status.Phase == corev1.PodRunning {
		return nil
	}
	return waitTimeoutForPodRunningInNamespace(c, pod.Name, pod.Namespace, defaultTimeout)
}

func waitTimeoutForPodRunningInNamespace(c kubernetes.Interface, podName, namespace string, timeout time.Duration) error {
	return wait.PollImmediate(Poll, defaultTimeout, podRunning(c, podName, namespace))
}

func waitForPodDeletion(c kubernetes.Interface, podName, namespace string) error {
	return wait.PollImmediate(Poll, defaultTimeout, podDeleted(c, podName, namespace))
}

func waitForHealthzCheck(cas [][]byte, url string) error {
	client, err := newHTTPSClient(cas)
	if err != nil {
		return err
	}
	return wait.PollImmediate(time.Second, 50*time.Second, func() (bool, error) {
		resp, err := getResponse(url+"/oauth/healthz", client)
		if err != nil {
			return false, err
		}
		if resp.StatusCode != 200 {
			return false, nil
		}
		resp.Body.Close()
		return true, nil
	})
}

func podDeleted(c kubernetes.Interface, podName, namespace string) wait.ConditionFunc {
	return func() (bool, error) {
		_, err := c.CoreV1().Pods(namespace).Get(podName, metav1.GetOptions{})
		if err != nil {
			if errors.IsNotFound(err) {
				return true, nil
			}
			return false, err
		}
		return false, nil
	}
}

func podRunning(c kubernetes.Interface, podName, namespace string) wait.ConditionFunc {
	return func() (bool, error) {
		pod, err := c.CoreV1().Pods(namespace).Get(podName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		switch pod.Status.Phase {
		case corev1.PodRunning:
			return true, nil
		case corev1.PodFailed, corev1.PodSucceeded:
			return false, fmt.Errorf("pod ran to completion")
		}
		return false, nil
	}
}

func waitUntilRouteIsReady(cas [][]byte, url string) error {
	client, err := newHTTPSClient(cas)
	if err != nil {
		return err
	}
	return wait.PollImmediate(time.Second, 30*time.Second, func() (bool, error) {
		resp, err := getResponse(url, client)
		if err != nil {
			if err.Error()[len(err.Error())-3:] == "EOF" {
				return false, nil
			}
			return false, err
		}
		resp.Body.Close()
		return true, nil
	})
}

func getResponse(host string, client *http.Client) (*http.Response, error) {
	req, err := http.NewRequest("GET", host, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func createParsedCertificate(template, parent *x509.Certificate, sigKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Self-signed
	if sigKey == nil {
		sigKey = key
	}

	raw, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), sigKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}

func encodeCert(certificate *x509.Certificate) ([]byte, error) {
	var certBytes bytes.Buffer
	wb := bufio.NewWriter(&certBytes)
	err := pem.Encode(wb, &pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	if err != nil {
		return nil, err
	}
	wb.Flush()
	return certBytes.Bytes(), nil
}

func encodeKey(key *rsa.PrivateKey) ([]byte, error) {
	var keyBytes bytes.Buffer
	wb := bufio.NewWriter(&keyBytes)
	err := pem.Encode(wb, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err != nil {
		return nil, err
	}
	wb.Flush()
	return keyBytes.Bytes(), nil
}

func newHTTPSClient(cas [][]byte) (*http.Client, error) {
	pool := x509.NewCertPool()
	for i := range cas {
		if !pool.AppendCertsFromPEM(cas[i]) {
			return nil, fmt.Errorf("error loading CA for client config")
		}
	}

	jar, _ := cookiejar.New(nil)
	tr := &http.Transport{
		MaxIdleConns:    10,
		IdleConnTimeout: 30 * time.Second,
		TLSClientConfig: oscrypto.SecureTLSConfig(&tls.Config{RootCAs: pool}),
	}

	client := &http.Client{Transport: tr, Jar: jar}
	return client, nil
}

func createCAandCertSet(host string) ([]byte, []byte, []byte, error) {
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour * 24 * 365)
	casub := pkix.Name{
		CommonName: "oauth-proxy-test-ca",
	}
	serverSubj := pkix.Name{
		CommonName: host,
	}

	caTemplate := &x509.Certificate{
		SignatureAlgorithm:    x509.SHA256WithRSA,
		SerialNumber:          big.NewInt(1),
		Issuer:                casub,
		Subject:               casub,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            10,
	}

	caCert, caKey, err := createParsedCertificate(caTemplate, caTemplate, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error creating certificate %s, %v", caTemplate.Subject.CommonName, err)
	}

	serverTemplate := &x509.Certificate{
		SignatureAlgorithm:    x509.SHA256WithRSA,
		SerialNumber:          big.NewInt(2),
		Issuer:                casub,
		Subject:               serverSubj,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              []string{host},
	}

	serverCert, serverKey, err := createParsedCertificate(serverTemplate, caCert, caKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error creating certificate %s, %v", caTemplate.Subject.CommonName, err)
	}

	pemCA, err := encodeCert(caCert)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error encoding CA cert %v", err)
	}
	pemServerCert, err := encodeCert(serverCert)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error encoding server cert %v", err)
	}
	pemServerKey, err := encodeKey(serverKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error encoding server key %v", err)
	}

	return pemCA, pemServerCert, pemServerKey, nil
}

func visit(n *html.Node, visitor func(*html.Node)) {
	visitor(n)
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		visit(c, visitor)
	}
}

func getTextNodes(root *html.Node) []*html.Node {
	elements := []*html.Node{}
	visit(root, func(n *html.Node) {
		if n.Type == html.TextNode {
			elements = append(elements, n)
		}
	})
	return elements
}

func getElementsByTagName(root *html.Node, tagName string) []*html.Node {
	elements := []*html.Node{}
	visit(root, func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == tagName {
			elements = append(elements, n)
		}
	})
	return elements
}

func getAttr(element *html.Node, attrName string) (string, bool) {
	for _, attr := range element.Attr {
		if attr.Key == attrName {
			return attr.Val, true
		}
	}
	return "", false
}

// Varying the login name for each test ensures we test a fresh grant
func randLogin() string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, 5)
	for i := range b {
		b[i] = letters[mathrand.Intn(len(letters))]
	}
	return "developer" + string(b)
}

// newRequestFromForm builds a request that simulates submitting the given form.
func newRequestFromForm(form *html.Node, currentURL *url.URL, user string) (*http.Request, error) {
	var (
		reqMethod string
		reqURL    *url.URL
		reqBody   io.Reader
		reqHeader = http.Header{}
		err       error
	)

	// Method defaults to GET if empty
	if method, _ := getAttr(form, "method"); len(method) > 0 {
		reqMethod = strings.ToUpper(method)
	} else {
		reqMethod = "GET"
	}

	// URL defaults to current URL if empty
	action, _ := getAttr(form, "action")
	reqURL, err = currentURL.Parse(action)
	if err != nil {
		return nil, err
	}

	formData := url.Values{}
	if reqMethod == "GET" {
		// Start with any existing query params when we're submitting via GET
		formData = reqURL.Query()
	}
	addedSubmit := false
	for _, input := range getElementsByTagName(form, "input") {
		if name, ok := getAttr(input, "name"); ok {
			if value, ok := getAttr(input, "value"); ok {
				inputType, _ := getAttr(input, "type")

				switch inputType {
				case "text":
					if name == "username" {
						formData.Add(name, user)
					}
				case "password":
					if name == "password" {
						formData.Add(name, "foo")
					}
				case "submit":
					// If this is a submit input, only add the value of the first one.
					// We're simulating submitting the form.
					if !addedSubmit {
						formData.Add(name, value)
						addedSubmit = true
					}
				case "radio", "checkbox":
					if _, checked := getAttr(input, "checked"); checked {
						formData.Add(name, value)
					}
				default:
					formData.Add(name, value)
				}
			}
		}
	}

	switch reqMethod {
	case "GET":
		reqURL.RawQuery = formData.Encode()
	case "POST":
		reqHeader.Set("Content-Type", "application/x-www-form-urlencoded")
		reqBody = strings.NewReader(formData.Encode())
	default:
		return nil, fmt.Errorf("unknown method: %s", reqMethod)
	}

	req, err := http.NewRequest(reqMethod, reqURL.String(), reqBody)
	if err != nil {
		return nil, err
	}

	req.Header = reqHeader
	return req, nil
}

// execCmd executes a command and returns the stdout + error, if any
func execCmd(cmd string, args []string, input string) (string, error) {
	c := exec.Command(cmd, args...)
	stdin, err := c.StdinPipe()
	if err != nil {
		return "", err
	}

	go func() {
		defer stdin.Close()
		if input != "" {
			io.WriteString(stdin, input)
		}
	}()

	out, err := c.CombinedOutput()
	if err != nil {
		fmt.Printf("Command '%s' failed with: %s\n", cmd, err)
		fmt.Printf("Output: %s\n", out)
		return "", err
	}
	return string(out), nil
}

func deleteTestRoute(routeName, namespace string) error {
	_, err := execCmd("oc", []string{"delete", fmt.Sprintf("route/%s", routeName), "-n", namespace}, "")
	if err != nil {
		return err
	}
	return nil
}

func getRouteHost(routeName, namespace string) (string, error) {
	out, err := execCmd("oc", []string{"get", fmt.Sprintf("route/%s", routeName), "-o", "jsonpath='{.spec.host}'", "-n", namespace}, "")
	if err != nil {
		return "", err
	}
	// strip surrounding single quotes
	return out[1 : len(out)-1], nil
}

func newOAuthProxyService() *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: "proxy",
			Labels: map[string]string{
				"app": "proxy",
			},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app": "proxy",
			},
			Ports: []corev1.ServicePort{
				{
					Protocol:   corev1.ProtocolTCP,
					Port:       int32(443),
					TargetPort: intstr.FromInt(8443),
				},
			},
		},
	}
}

var routeYaml = `apiVersion: v1
kind: Route
metadata:
  labels:
    app: proxy
  name: proxy-route
spec:
  port:
    targetPort: 8443
  to:
    kind: Service
    name: proxy
    weight: 100
  wildcardPolicy: None
  tls:
    termination: passthrough
`

// create a route using oc create directly
func newOAuthProxyRoute(namespace string) error {
	_, err := execCmd("oc", []string{"create", "-n", namespace, "-f", "-"}, routeYaml)
	return err
}

func newOAuthProxySA() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name: "proxy",
			Annotations: map[string]string{
				"serviceaccounts.openshift.io/oauth-redirectreference.primary": `{"kind":"OAuthRedirectReference","apiVersion":"v1","reference":{"kind":"Route","name":"proxy-route"}}`,
			},
		},
	}
}

func newOAuthProxyConfigMap(namespace string, pemCA, pemServerCert, pemServerKey, upstreamCA, upstreamCert, upstreamKey []byte) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "proxy-certs",
			Namespace: namespace,
		},
		Data: map[string]string{
			"ca.crt":         "|\n" + string(pemCA),
			"tls.crt":        "|\n" + string(pemServerCert),
			"tls.key":        "|\n" + string(pemServerKey),
			"upstreamca.crt": "|\n" + string(upstreamCA),
			"upstream.crt":   "|\n" + string(upstreamCert),
			"upstream.key":   "|\n" + string(upstreamKey),
		},
	}
}

func newOAuthProxyPod(proxyImage, backendImage string, proxyArgs, backendEnvs []string) *corev1.Pod {
	backendEnvVars := []corev1.EnvVar{}
	for _, env := range backendEnvs {
		e := strings.Split(env, "=")
		if len(e) <= 1 {
			continue
		}
		backendEnvVars = append(backendEnvVars, corev1.EnvVar{Name: e[0], Value: e[1]})
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "proxy",
			Labels: map[string]string{
				"app": "proxy",
			},
		},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{
				{
					Name: "proxy-cert-volume",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: "proxy-certs"},
						},
					},
				},
			},
			ServiceAccountName: "proxy",
			Containers: []corev1.Container{
				{
					Image:           proxyImage,
					ImagePullPolicy: corev1.PullIfNotPresent,
					Name:            "oauth-proxy",
					Args:            proxyArgs,
					Ports: []corev1.ContainerPort{
						{
							ContainerPort: 8443,
						},
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							MountPath: "/etc/tls/private",
							Name:      "proxy-cert-volume",
						},
					},
				},
				{
					Image: backendImage,
					Name:  "hello-openshift",
					Ports: []corev1.ContainerPort{
						{
							ContainerPort: 8080,
						},
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							MountPath: "/etc/tls/private",
							Name:      "proxy-cert-volume",
						},
					},
					Env: backendEnvVars,
				},
			},
		},
	}
}
