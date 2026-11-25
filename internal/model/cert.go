package model

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
)

// RetryConditions maps Retry.On values to their nginx names.
var RetryConditions = map[string]bool{
	"error": true, "timeout": true, "http_500": true, "http_502": true, "http_503": true,
	"http_504": true, "http_403": true, "http_404": true, "http_429": true, "non_idempotent": true,
}

// ParseCertificate checks that chainPEM holds certificates whose first one
// matches keyPEM, and returns what the API shows about it.
func ParseCertificate(chainPEM, keyPEM string) (CertStatus, error) {
	pair, err := tls.X509KeyPair([]byte(chainPEM), []byte(keyPEM))
	if err != nil {
		return CertStatus{}, fmt.Errorf("certificate and key: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return CertStatus{}, errors.New("no certificate")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return CertStatus{}, err
	}
	if _, ok := pair.PrivateKey.(crypto.Signer); !ok {
		return CertStatus{}, errors.New("unsupported private key")
	}
	return CertStatus{
		Subject:  leaf.Subject.CommonName,
		DNSNames: slices.Clone(leaf.DNSNames),
		NotAfter: leaf.NotAfter.UTC(),
	}, nil
}

// Prepare sets the fields the control plane derives from r before it is
// stored: the status of an uploaded certificate.
func Prepare(r Resource) {
	if c, ok := r.(*Certificate); ok && c.Spec.Source != CertACME {
		st, err := ParseCertificate(c.Spec.ChainPEM, c.Spec.KeyPEM)
		if err != nil {
			st.Error = err.Error()
		}
		c.Spec.Status = st
	}
}

// Redacted returns r as the API shows it: private keys are never returned.
func Redacted(r Resource) Resource {
	c, ok := r.(*Certificate)
	if !ok || c.Spec.KeyPEM == "" {
		return r
	}
	out := *c
	out.Spec.KeyPEM = ""
	return &out
}
