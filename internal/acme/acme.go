// Package acme issues and renews certificates of source "acme". The control
// plane runs the ACME client; proxies only answer the HTTP-01 and
// TLS-ALPN-01 challenges it hands them.
package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"
	distribv1 "github.com/null-variable/proxelo-api/gen/go/proxelo/distrib/v1"

	"github.com/null-variable/proxelo/internal/model"
	"github.com/null-variable/proxelo/internal/store"
)

// LetsEncrypt is the default directory.
const LetsEncrypt = "https://acme-v02.api.letsencrypt.org/directory"

// renewBefore is how long before expiry a certificate is renewed.
const renewBefore = 30 * 24 * time.Hour

// Challenges receives the challenges proxies must answer.
type Challenges interface {
	SetChallenges(*distribv1.Challenges)
}

// Config sets up the manager.
type Config struct {
	// ACME directory URL.
	Directory string
	// Contact email for the account, optional.
	Email string
	// Interval between renewal checks.
	Interval time.Duration
	// Applied after a certificate is issued, so proxies get it. Returns an
	// error when the new revision cannot be made.
	Apply func(ctx context.Context, cert *model.Certificate) error
}

// Manager issues certificates in the background.
type Manager struct {
	cfg Config
	st  *store.Store
	ch  Challenges
	log *slog.Logger

	mu sync.Mutex
	// Active challenges by token (HTTP-01) and name (TLS-ALPN-01).
	http map[string]string
	alpn map[string]*distribv1.TlsAlpnChallenge
	// Next attempt per certificate ID after a failure.
	backoff map[string]backoff
	wake    chan struct{}
}

type backoff struct {
	at    time.Time
	delay time.Duration
}

func New(cfg Config, st *store.Store, ch Challenges, log *slog.Logger) *Manager {
	if cfg.Directory == "" {
		cfg.Directory = LetsEncrypt
	}
	if cfg.Interval == 0 {
		cfg.Interval = time.Hour
	}
	return &Manager{
		cfg: cfg, st: st, ch: ch, log: log,
		http:    map[string]string{},
		alpn:    map[string]*distribv1.TlsAlpnChallenge{},
		backoff: map[string]backoff{},
		wake:    make(chan struct{}, 1),
	}
}

// Kick runs a check soon, for example after a certificate was created.
func (m *Manager) Kick() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// Run checks certificates until ctx ends.
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(m.cfg.Interval)
	defer t.Stop()
	for {
		m.check(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-m.wake:
		}
	}
}

// due reports whether c needs a certificate now.
func due(c *model.Certificate, now time.Time) bool {
	if c.Spec.ChainPEM == "" || c.Spec.KeyPEM == "" {
		return true
	}
	st := c.Spec.Status
	if st.NotAfter.IsZero() || st.NotAfter.Sub(now) < renewBefore {
		return true
	}
	// Domains changed since issuance.
	names := slices.Clone(st.DNSNames)
	want := slices.Clone(c.Spec.Domains)
	slices.Sort(names)
	slices.Sort(want)
	return !slices.Equal(names, want)
}

func (m *Manager) check(ctx context.Context) {
	all, err := m.st.List(ctx, model.CertificateKind)
	if err != nil {
		m.log.Error("acme: listing certificates", "err", err)
		return
	}
	now := time.Now()
	for _, r := range all {
		c := r.(*model.Certificate)
		if c.Spec.Source != model.CertACME || !c.IsEnabled() || !due(c, now) {
			continue
		}
		m.mu.Lock()
		b := m.backoff[c.ID]
		m.mu.Unlock()
		if now.Before(b.at) {
			continue
		}
		if err := m.issue(ctx, c); err != nil {
			delay := min(max(b.delay*2, time.Minute), 24*time.Hour)
			m.mu.Lock()
			m.backoff[c.ID] = backoff{at: time.Now().Add(delay), delay: delay}
			m.mu.Unlock()
			m.log.Error("acme: issuing", "certificate", c.ID, "domains", c.Spec.Domains, "retryIn", delay, "err", err)
			st := c.Spec.Status
			st.Error = err.Error()
			if _, serr := m.st.SetCertificate(ctx, c.ID, c.Spec.ChainPEM, c.Spec.KeyPEM, st); serr != nil {
				m.log.Error("acme: storing error", "certificate", c.ID, "err", serr)
			}
			continue
		}
		m.mu.Lock()
		delete(m.backoff, c.ID)
		m.mu.Unlock()
	}
}

// account loads or registers the ACME account.
func (m *Manager) account(ctx context.Context, client *acmez.Client) (acme.Account, error) {
	type stored struct {
		Location string `json:"location"`
		KeyPEM   string `json:"keyPem"`
	}
	key := "acme/account/" + m.cfg.Directory
	if b, err := m.st.Value(ctx, key); err == nil {
		var s stored
		if err := json.Unmarshal(b, &s); err != nil {
			return acme.Account{}, err
		}
		block, _ := pem.Decode([]byte(s.KeyPEM))
		if block == nil {
			return acme.Account{}, errors.New("stored account key is not PEM")
		}
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return acme.Account{}, err
		}
		signer, ok := k.(crypto.Signer)
		if !ok {
			return acme.Account{}, errors.New("stored account key cannot sign")
		}
		return client.GetAccount(ctx, acme.Account{Location: s.Location, PrivateKey: signer})
	} else if !errors.Is(err, store.ErrNotFound) {
		return acme.Account{}, err
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return acme.Account{}, err
	}
	acct := acme.Account{TermsOfServiceAgreed: true, PrivateKey: k}
	if m.cfg.Email != "" {
		acct.Contact = []string{"mailto:" + m.cfg.Email}
	}
	acct, err = client.NewAccount(ctx, acct)
	if err != nil {
		return acct, fmt.Errorf("registering account: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return acct, err
	}
	b, err := json.Marshal(stored{Location: acct.Location, KeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))})
	if err != nil {
		return acct, err
	}
	return acct, m.st.Put(ctx, key, b)
}

func (m *Manager) issue(ctx context.Context, c *model.Certificate) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	client := &acmez.Client{
		Client: &acme.Client{Directory: m.cfg.Directory, Logger: m.log},
		ChallengeSolvers: map[string]acmez.Solver{
			acme.ChallengeTypeHTTP01:    httpSolver{m},
			acme.ChallengeTypeTLSALPN01: alpnSolver{m},
		},
	}
	acct, err := m.account(ctx, client)
	if err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	certs, err := client.ObtainCertificateForSANs(ctx, acct, key, c.Spec.Domains)
	if err != nil {
		return err
	}
	if len(certs) == 0 {
		return errors.New("no certificate returned")
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	chain := string(certs[0].ChainPEM)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	st, err := model.ParseCertificate(chain, keyPEM)
	if err != nil {
		return err
	}
	updated, err := m.st.SetCertificate(ctx, c.ID, chain, keyPEM, st)
	if err != nil {
		return err
	}
	m.log.Info("acme: issued", "certificate", c.ID, "domains", c.Spec.Domains, "notAfter", st.NotAfter)
	if m.cfg.Apply != nil {
		return m.cfg.Apply(ctx, updated)
	}
	return nil
}

// publish sends the current challenge set to every proxy.
func (m *Manager) publish() {
	out := &distribv1.Challenges{}
	for token, ka := range m.http {
		out.Http01 = append(out.Http01, &distribv1.HttpChallenge{Token: token, KeyAuthorization: ka})
	}
	for _, c := range m.alpn {
		out.TlsAlpn01 = append(out.TlsAlpn01, c)
	}
	slices.SortFunc(out.Http01, func(a, b *distribv1.HttpChallenge) int { return strings.Compare(a.Token, b.Token) })
	slices.SortFunc(out.TlsAlpn01, func(a, b *distribv1.TlsAlpnChallenge) int { return strings.Compare(a.Name, b.Name) })
	m.ch.SetChallenges(out)
}

// presentWait gives proxies time to receive a challenge before the CA
// checks it.
const presentWait = 2 * time.Second

type httpSolver struct{ m *Manager }

func (s httpSolver) Present(_ context.Context, c acme.Challenge) error {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	s.m.http[c.Token] = c.KeyAuthorization
	s.m.publish()
	return nil
}

func (s httpSolver) Wait(ctx context.Context, _ acme.Challenge) error {
	return sleep(ctx, presentWait)
}

func (s httpSolver) CleanUp(_ context.Context, c acme.Challenge) error {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	delete(s.m.http, c.Token)
	s.m.publish()
	return nil
}

type alpnSolver struct{ m *Manager }

func (s alpnSolver) Present(_ context.Context, c acme.Challenge) error {
	cert, err := acmez.TLSALPN01ChallengeCert(c)
	if err != nil {
		return err
	}
	chain, key, err := certPEM(cert)
	if err != nil {
		return err
	}
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	s.m.alpn[c.Identifier.Value] = &distribv1.TlsAlpnChallenge{Name: c.Identifier.Value, ChainPem: chain, KeyPem: key}
	s.m.publish()
	return nil
}

func (s alpnSolver) Wait(ctx context.Context, _ acme.Challenge) error {
	return sleep(ctx, presentWait)
}

func (s alpnSolver) CleanUp(_ context.Context, c acme.Challenge) error {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	delete(s.m.alpn, c.Identifier.Value)
	s.m.publish()
	return nil
}

func certPEM(c *tls.Certificate) (chain, key string, err error) {
	for _, der := range c.Certificate {
		chain += string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	k, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		return "", "", err
	}
	return chain, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k})), nil
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
