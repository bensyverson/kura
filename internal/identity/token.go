package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	// ErrUnauthenticated means no credential was presented. The request
	// resolves to no principal — this is the no-anonymous-path rule.
	ErrUnauthenticated = errors.New("identity: no credentials presented")

	// ErrTokenInvalid means the token is malformed, or its signature
	// does not verify against the signing secret.
	ErrTokenInvalid = errors.New("identity: token is invalid")

	// ErrTokenExpired means the token's signature verified but it is
	// past its expiry.
	ErrTokenExpired = errors.New("identity: token has expired")
)

// Authenticator issues and resolves short-lived identity tokens.
//
// A token is self-contained and HMAC-SHA256 signed: it carries the
// principal and an expiry, and the signature is verified on every
// resolve. There is one fixed algorithm — no algorithm negotiation, so
// no algorithm-confusion attack surface. The signing secret is injected
// (it comes from the secrets manager in a deployed system), so this core
// type has no storage or network dependency and is trivially testable.
type Authenticator struct {
	secret []byte
	now    func() time.Time // injectable for tests
}

// NewAuthenticator returns an Authenticator that signs and verifies with
// secret.
func NewAuthenticator(secret []byte) *Authenticator {
	return &Authenticator{secret: secret, now: time.Now}
}

// tokenEncoding is unpadded base64url — URL- and header-safe, no '='.
var tokenEncoding = base64.RawURLEncoding

// claims is the wire payload of a token.
type claims struct {
	Type   PrincipalType `json:"typ"`
	ID     string        `json:"sub"`
	Email  string        `json:"email,omitempty"`
	Tenant string        `json:"tenant,omitempty"`
	Iat    int64         `json:"iat"`
	Exp    int64         `json:"exp"`
}

// Issue mints a signed token for p that expires ttl from now. It refuses
// to mint a token for a malformed principal — an invalid principal must
// never become a credential.
func (a *Authenticator) Issue(p Principal, ttl time.Duration) (string, error) {
	if err := p.Valid(); err != nil {
		return "", err
	}
	now := a.now()
	payload, err := json.Marshal(claims{
		Type:   p.Type,
		ID:     p.ID,
		Email:  p.Email,
		Tenant: p.Tenant,
		Iat:    now.Unix(),
		Exp:    now.Add(ttl).Unix(),
	})
	if err != nil {
		return "", fmt.Errorf("identity: encode token: %w", err)
	}
	body := tokenEncoding.EncodeToString(payload)
	return body + "." + tokenEncoding.EncodeToString(a.sign(body)), nil
}

// Resolve turns a raw credential into the principal it represents.
//
//   - An empty credential is ErrUnauthenticated — no anonymous path.
//   - A malformed token, or one whose signature does not verify, is
//     ErrTokenInvalid.
//   - A verified-but-expired token is ErrTokenExpired.
//
// Only a fully valid token yields a principal; every error path returns
// the zero Principal.
func (a *Authenticator) Resolve(raw string) (Principal, error) {
	if raw == "" {
		return Principal{}, ErrUnauthenticated
	}
	body, sig, ok := strings.Cut(raw, ".")
	if !ok {
		return Principal{}, ErrTokenInvalid
	}

	// Verify the signature before trusting any byte of the payload.
	gotSig, err := tokenEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(gotSig, a.sign(body)) {
		return Principal{}, ErrTokenInvalid
	}

	payload, err := tokenEncoding.DecodeString(body)
	if err != nil {
		return Principal{}, ErrTokenInvalid
	}
	var c claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return Principal{}, ErrTokenInvalid
	}
	if a.now().Unix() >= c.Exp {
		return Principal{}, ErrTokenExpired
	}
	return Principal{Type: c.Type, ID: c.ID, Email: c.Email, Tenant: c.Tenant}, nil
}

// sign returns the HMAC-SHA256 of body under the signing secret.
func (a *Authenticator) sign(body string) []byte {
	mac := hmac.New(sha256.New, a.secret)
	mac.Write([]byte(body))
	return mac.Sum(nil)
}
