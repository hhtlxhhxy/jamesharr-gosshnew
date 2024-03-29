// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"
)

// These constants from [PROTOCOL.certkeys] represent the algorithm names
// for certificate types supported by this package.
const (
	CertAlgoRSAv01      = "ssh-rsa-cert-v01@openssh.com"
	CertAlgoDSAv01      = "ssh-dss-cert-v01@openssh.com"
	CertAlgoECDSA256v01 = "ecdsa-sha2-nistp256-cert-v01@openssh.com"
	CertAlgoECDSA384v01 = "ecdsa-sha2-nistp384-cert-v01@openssh.com"
	CertAlgoECDSA521v01 = "ecdsa-sha2-nistp521-cert-v01@openssh.com"
)

// Certificate types are used to specify whether a certificate is for identification
// of a user or a host.  Current identities are defined in [PROTOCOL.certkeys].
const (
	UserCert = 1
	HostCert = 2
)

type Signature struct {
	Format string
	Blob   []byte
}

const (
	CertTimeInfinity = 1<<64 - 1
	maxInt64         = 1<<63 - 1
)

// CertTime represents an unsigned 64-bit time value in seconds starting from
// UNIX epoch.  We use CertTime instead of time.Time in order to properly handle
// the "infinite" time value ^0, which would become negative when expressed as
// an int64.
type CertTime uint64

func (ct CertTime) Time() time.Time {
	if ct > maxInt64 {
		return time.Unix(maxInt64, 0)
	}
	return time.Unix(int64(ct), 0)
}

func (ct CertTime) IsInfinite() bool {
	return ct == CertTimeInfinity
}

// An OpenSSHCertV01 represents an OpenSSH certificate as defined in
// [PROTOCOL.certkeys]?rev=1.8.
type OpenSSHCertV01 struct {
	Nonce                   []byte
	Key                     PublicKey
	Serial                  uint64
	Type                    uint32
	KeyId                   string
	ValidPrincipals         []string
	ValidAfter, ValidBefore CertTime
	CriticalOptions         map[string]string
	Extensions              map[string]string
	Reserved                []byte
	SignatureKey            PublicKey
	Signature               *Signature
}

// genericCertData holds the key-independent part of the cert data:
// all certs look like {Nonce, public key fields, generic data
// fields}.
type genericCertData struct {
	Serial          uint64
	Type            uint32
	KeyId           string
	ValidPrincipals []byte
	ValidAfter      uint64
	ValidBefore     uint64
	CriticalOptions []byte
	Extensions      []byte
	Reserved        []byte
	SignatureKey    []byte
	Signature       []byte
}

func marshalStringList(namelist []string) []byte {
	var to []byte
	for _, name := range namelist {
		s := struct{ N string }{name}
		to = append(to, Marshal(s)...)
	}
	return to
}

func marshalTuples(tups map[string]string) []byte {
	keys := make([]string, 0, len(tups))
	for k := range tups {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var r []byte
	for _, k := range keys {
		s := struct{ K, V string }{k, tups[k]}
		r = append(r, Marshal(s)...)
	}
	return r
}

func parseTuples(in []byte) (map[string]string, error) {
	tups := map[string]string{}
	for len(in) > 0 {
		nameBytes, rest, ok := parseString(in)
		if !ok {
			return nil, errShortRead
		}
		data, rest, ok := parseString(rest)
		if !ok {
			return nil, errShortRead
		}
		name := string(nameBytes)
		if _, ok := tups[name]; ok {
			return nil, fmt.Errorf("duplicate key %s", name)
		}
		tups[name] = string(data)
		in = rest
	}
	return tups, nil
}

func parseCert(in []byte, privAlgo string) (*OpenSSHCertV01, error) {
	nonce, rest, ok := parseString(in)
	if !ok {
		return nil, errShortRead
	}
	c := &OpenSSHCertV01{
		Nonce: nonce,
	}

	var err error
	c.Key, rest, err = parsePubKey(rest, privAlgo)
	if err != nil {
		return nil, err
	}

	var g genericCertData
	if err := Unmarshal(rest, &g); err != nil {
		return nil, err
	}
	c.Serial = g.Serial
	c.Type = g.Type
	c.KeyId = g.KeyId

	p := g.ValidPrincipals
	for len(p) > 0 {
		principal, rest, ok := parseString(p)
		if !ok {
			return nil, errShortRead
		}
		c.ValidPrincipals = append(c.ValidPrincipals, string(principal))
		p = rest
	}

	c.ValidAfter = CertTime(g.ValidAfter)
	c.ValidBefore = CertTime(g.ValidBefore)

	c.CriticalOptions, err = parseTuples(g.CriticalOptions)
	if err != nil {
		return nil, err
	}
	c.Extensions, err = parseTuples(g.Extensions)
	if err != nil {
		return nil, err
	}
	c.Reserved = g.Reserved
	k, err := ParsePublicKey(g.SignatureKey)
	if err != nil {
		return nil, err
	}

	c.SignatureKey = k
	c.Signature, rest, ok = parseSignatureBody(g.Signature)
	if !ok || len(rest) > 0 {
		return nil, errors.New("ssh: signature parse error")
	}

	return c, nil
}

type openSSHCertSigner struct {
	pub    *OpenSSHCertV01
	signer Signer
}

// NewCertSigner constructs a Signer whose public key is the given
// certificate. The public key in cert.Key should be the same as
// signer.PublicKey().
func NewCertSigner(cert *OpenSSHCertV01, signer Signer) (Signer, error) {
	if bytes.Compare(cert.Key.Marshal(), signer.PublicKey().Marshal()) != 0 {
		return nil, errors.New("ssh: signer and cert have different public key")
	}

	return &openSSHCertSigner{cert, signer}, nil
}

func (s *openSSHCertSigner) Sign(rand io.Reader, data []byte) (*Signature, error) {
	return s.signer.Sign(rand, data)
}

func (s *openSSHCertSigner) PublicKey() PublicKey {
	return s.pub
}

// Validate checks the signature and timestamp on the certificate.
// Before accepting a cert for user login, the following other
// information should be verified: whether all CriticalOptions are
// recognized, whether the signature key is a user CA, whether the key
// Serial has been revoked, if the Type is a UserCert, whether the
// username matches ValidPrincipal, and whether the remote address
// matches the source-address CriticalOption if given. The latter two
// are available in ConnMetadata argument of the server auth
// callbacks.
func (c *OpenSSHCertV01) Validate(now time.Time) bool {
	unixNow := CertTime(now.Unix())
	if unixNow < c.ValidAfter {
		return false
	}
	if !c.ValidBefore.IsInfinite() && unixNow >= c.ValidBefore {
		return false
	}
	return c.SignatureKey.Verify(c.bytesForSigning(), c.Signature)
}

// SignCert sets the SignatureKey to the authority's public key, and
// stores a Signature by the authority in the certificate.
func (c *OpenSSHCertV01) SignCert(authority Signer) error {
	// Should set Nonce on the cert before signing?
	pub := authority.PublicKey()

	c.Nonce = make([]byte, 32)
	rand.Reader.Read(c.Nonce)
	c.SignatureKey = pub

	// Should get rand from some config?
	sig, err := authority.Sign(rand.Reader, c.bytesForSigning())
	if err != nil {
		return err
	}
	c.Signature = sig
	return nil
}

var certAlgoNames = map[string]string{
	KeyAlgoRSA:      CertAlgoRSAv01,
	KeyAlgoDSA:      CertAlgoDSAv01,
	KeyAlgoECDSA256: CertAlgoECDSA256v01,
	KeyAlgoECDSA384: CertAlgoECDSA384v01,
	KeyAlgoECDSA521: CertAlgoECDSA521v01,
}

// certToPrivAlgo returns the underlying algorithm for a certificate algorithm.
// Panics if a non-certificate algorithm is passed.
func certToPrivAlgo(algo string) string {
	for privAlgo, pubAlgo := range certAlgoNames {
		if pubAlgo == algo {
			return privAlgo
		}
	}
	panic("unknown cert algorithm")
}

func (cert *OpenSSHCertV01) bytesForSigning() []byte {
	c2 := *cert
	c2.Signature = nil
	out := c2.Marshal()
	// Drop trailing signature length.
	return out[:len(out)-4]
}

func (c *OpenSSHCertV01) Marshal() []byte {
	generic := genericCertData{
		Serial:          c.Serial,
		Type:            c.Type,
		KeyId:           c.KeyId,
		ValidPrincipals: marshalStringList(c.ValidPrincipals),
		ValidAfter:      uint64(c.ValidAfter),
		ValidBefore:     uint64(c.ValidBefore),
		CriticalOptions: marshalTuples(c.CriticalOptions),
		Extensions:      marshalTuples(c.Extensions),
		Reserved:        c.Reserved,
		SignatureKey:    c.SignatureKey.Marshal(),
	}
	if c.Signature != nil {
		generic.Signature = Marshal(*c.Signature)
	}
	genericBytes := Marshal(generic)
	keyBytes := c.Key.Marshal()
	_, keyBytes, _ = parseString(keyBytes)
	prefix := Marshal(struct {
		Name  string
		Nonce []byte
		Key   []byte `ssh:"rest"`
	}{c.PublicKeyAlgo(), c.Nonce, keyBytes})

	result := make([]byte, len(prefix)+len(genericBytes))
	dst := result
	copy(dst, prefix)
	dst = dst[len(prefix):]
	copy(dst, genericBytes)
	return result
}

func (c *OpenSSHCertV01) PublicKeyAlgo() string {
	algo, ok := certAlgoNames[c.Key.PublicKeyAlgo()]
	if !ok {
		panic("unknown cert key type")
	}
	return algo
}

func (c *OpenSSHCertV01) Verify(data []byte, sig *Signature) bool {
	return c.Key.Verify(data, sig)
}

func parseSignatureBody(in []byte) (out *Signature, rest []byte, ok bool) {
	var format []byte
	if format, in, ok = parseString(in); !ok {
		return
	}

	out = &Signature{
		Format: string(format),
	}

	if out.Blob, in, ok = parseString(in); !ok {
		return
	}

	return out, in, ok
}

func parseSignature(in []byte) (out *Signature, rest []byte, ok bool) {
	var sigBytes []byte
	if sigBytes, rest, ok = parseString(in); !ok {
		return
	}

	out, sigBytes, ok = parseSignatureBody(sigBytes)
	if !ok || len(sigBytes) > 0 {
		return nil, nil, false
	}
	return
}
