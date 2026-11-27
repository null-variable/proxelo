package model

import "testing"

func TestSecretsRedactedAndKept(t *testing.T) {
	stored := &Policy{Spec: PolicySpec{Type: PolicyOIDC, OIDC: &OIDCPolicy{Issuer: "https://idp", ClientID: "a", ClientSecret: "s"}}}
	shown := Redacted(stored).(*Policy)
	if shown.Spec.OIDC.ClientSecret != "" || stored.Spec.OIDC.ClientSecret != "s" {
		t.Fatalf("redacted %q, stored %q", shown.Spec.OIDC.ClientSecret, stored.Spec.OIDC.ClientSecret)
	}
	KeepSecrets(shown, stored)
	if shown.Spec.OIDC.ClientSecret != "s" {
		t.Errorf("kept %q", shown.Spec.OIDC.ClientSecret)
	}
	cert := &Certificate{Spec: CertificateSpec{KeyPEM: "k"}}
	back := Redacted(cert).(*Certificate)
	KeepSecrets(back, cert)
	if back.Spec.KeyPEM != "k" {
		t.Errorf("key %q", back.Spec.KeyPEM)
	}
}
