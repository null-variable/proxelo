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

// SecretFields are the JSON names of fields the API never returns.
var SecretFields = []string{"keyPem", "clientSecret"}

// Redacted returns r as the API shows it: private keys and client secrets
// are never returned.
func Redacted(r Resource) Resource {
	switch v := r.(type) {
	case *Certificate:
		if v.Spec.KeyPEM != "" {
			out := *v
			out.Spec.KeyPEM = ""
			return &out
		}
	case *Policy:
		if o := v.Spec.OIDC; o != nil && o.ClientSecret != "" {
			out := *v
			oc := *o
			oc.ClientSecret = ""
			out.Spec.OIDC = &oc
			return &out
		}
	}
	return r
}

// KeepSecrets fills the secret fields r leaves empty from cur, the stored
// version, so a resource read back from the API can be written again.
func KeepSecrets(r, cur Resource) {
	switch v := r.(type) {
	case *Certificate:
		if c, ok := cur.(*Certificate); ok && v.Spec.KeyPEM == "" {
			v.Spec.KeyPEM = c.Spec.KeyPEM
		}
	case *Policy:
		if c, ok := cur.(*Policy); ok && v.Spec.OIDC != nil && v.Spec.OIDC.ClientSecret == "" && c.Spec.OIDC != nil {
			v.Spec.OIDC.ClientSecret = c.Spec.OIDC.ClientSecret
		}
	}
}
