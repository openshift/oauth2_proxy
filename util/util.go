package util

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
)

func GetCertPool(paths []string) (*x509.CertPool, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("Invalid empty list of Root CAs file paths")
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("could not create system cert pool - %s", err)
	}
	for _, path := range paths {
		data, err := ioutil.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("certificate authority file (%s) could not be read - %s", path, err)
		}
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("loading certificate authority (%s) failed", path)
		}
	}
	return pool, nil
}
