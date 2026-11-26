// Package auth holds the admin credential primitives:
// Argon2id password hashes, TOTP second factors, random secrets and roles.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters (RFC 9106 second recommended option).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
	saltLen      = 16
)

// MinPasswordLen is the shortest password accepted.
const MinPasswordLen = 12

// HashPassword returns an encoded Argon2id hash of password.
func HashPassword(password string) string {
	salt := make([]byte, saltLen)
	rand.Read(salt)
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads, enc.EncodeToString(salt), enc.EncodeToString(key))
}

// CheckPassword reports whether password matches an encoded hash.
func CheckPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var v int
	var m uint32
	var t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[2], "v=%d", &v); err != nil || v != argon2.Version {
		return false
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	enc := base64.RawStdEncoding
	salt, err := enc.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := enc.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// dummyHash is checked against when no account matches, so a login takes
// as long for unknown names as for wrong passwords.
var dummyHash = HashPassword("proxelo-dummy-password")

// CheckNoUser spends the time of one password check.
func CheckNoUser(password string) { CheckPassword(dummyHash, password) }

// ValidatePassword rejects passwords that are too short.
func ValidatePassword(p string) error {
	if len(p) < MinPasswordLen {
		return fmt.Errorf("must be at least %d characters", MinPasswordLen)
	}
	return nil
}

// Secret returns n random bytes encoded for URLs and headers.
func Secret(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Hash is the stored form of a session or token secret.
func Hash(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}

// TOTP (RFC 6238): SHA-1, 6 digits, 30 second steps.
const (
	totpPeriod = 30
	totpDigits = 6
	// Codes from one step before or after are accepted for clock skew.
	totpSkew = 1
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a random 160-bit secret in base32.
func NewTOTPSecret() string {
	b := make([]byte, 20)
	rand.Read(b)
	return b32.EncodeToString(b)
}

// TOTPURI is the otpauth:// URI authenticator apps scan.
func TOTPURI(issuer, account, secret string) string {
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("period", fmt.Sprint(totpPeriod))
	v.Set("digits", fmt.Sprint(totpDigits))
	return "otpauth://totp/" + url.PathEscape(issuer+":"+account) + "?" + v.Encode()
}

func totpCode(key []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	n := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", totpDigits, n%1_000_000)
}

// TOTPCode returns the code for secret at t.
func TOTPCode(secret string, t time.Time) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", err
	}
	return totpCode(key, t.Unix()/totpPeriod), nil
}

// CheckTOTP returns the time step code is valid for at now. Callers must
// refuse a step not newer than the last one used, so each code works once.
func CheckTOTP(secret, code string, now time.Time) (int64, bool) {
	key, err := b32.DecodeString(strings.ToUpper(secret))
	if err != nil || len(code) != totpDigits {
		return 0, false
	}
	cur := now.Unix() / totpPeriod
	for d := int64(-totpSkew); d <= totpSkew; d++ {
		if subtle.ConstantTimeCompare([]byte(totpCode(key, cur+d)), []byte(code)) == 1 {
			return cur + d, true
		}
	}
	return 0, false
}

// Role is an admin role, from most to least privileged.
type Role string

const (
	Owner Role = "owner"
	// Everything but managing owners.
	Admin Role = "admin"
	// Applies, confirms and rolls back.
	Operator Role = "operator"
	// Edits change sets; applying needs an operator.
	Editor Role = "editor"
	Viewer Role = "viewer"
	// Signs in but reaches only the groups the account is a member of.
	Guest Role = "guest"
)

var ranks = map[Role]int{Guest: 1, Viewer: 2, Editor: 3, Operator: 4, Admin: 5, Owner: 6}

// ParseRole rejects unknown roles.
func ParseRole(s string) (Role, error) {
	r := Role(s)
	if ranks[r] == 0 {
		return "", errors.New(`must be "owner", "admin", "operator", "editor", "viewer" or "guest"`)
	}
	return r, nil
}

// ParseGroupRole accepts the roles a group can grant: "viewer" (read),
// "editor" (write to change sets), "operator" (apply) and "admin" (manage
// members and subgroups).
func ParseGroupRole(s string) (Role, error) {
	switch r := Role(s); r {
	case Viewer, Editor, Operator, Admin:
		return r, nil
	}
	return "", errors.New(`must be "admin", "operator", "editor" or "viewer"`)
}

// Higher returns the more privileged of r and o.
func (r Role) Higher(o Role) Role {
	if ranks[o] > ranks[r] {
		return o
	}
	return r
}

// Allows reports whether r has at least the privileges of min.
func (r Role) Allows(min Role) bool { return ranks[r] >= ranks[min] }

// Lower returns the less privileged of r and o.
func (r Role) Lower(o Role) Role {
	if ranks[o] < ranks[r] {
		return o
	}
	return r
}
