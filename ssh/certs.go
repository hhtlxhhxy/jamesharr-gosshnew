// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
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

type signature struct {
	Format string
	Blob   []byte
}

type tuple struct {
	Name string
	Data string
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
	CriticalOptions         []tuple // TODO(hanwen): use map type instead.
	Extensions              []tuple // TODO(hanwen): use map type instead.
	Reserved                []byte
	SignatureKey            PublicKey
	Signature               *signature // TODO(hanwen): use public type
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

func marshalTuples(tups []tuple) []byte {
	var r []byte
	// TODO(hanwen): fields should be sorted lexicographically
	for _, t := range tups {
		s := struct{ K, V string }{t.Name, t.Data}
		r = append(r, Marshal(s)...)
	}
	return r
}

func parseTuples(in []byte) ([]tuple, error) {
	var t []tuple
	for len(in) > 0 {
		name, rest, ok := parseString(in)
		if !ok {
			return nil, errShortRead
		}
		data, rest, ok := parseString(rest)
		if !ok {
			return nil, errShortRead
		}
		t = append(t, tuple{string(name), string(data)})
		in = rest
	}
	return t, nil
}

func parseCert(in []byte, privAlgo string) (*OpenSSHCertV01, error) {
	nonce, rest, ok := parseString(in)
	if !ok {
		return nil, errShortRead
	}
	c := &OpenSSHCertV01{
		Nonce: nonce,
	}

	c.Key, rest, ok = parsePubKey(rest, privAlgo)
	if !ok {
		return nil, errors.New("ssh: ParsePublicKey failed")
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

	var err error
	c.CriticalOptions, err = parseTuples(g.CriticalOptions)
	if err != nil {
		return nil, err
	}
	c.Extensions, err = parseTuples(g.Extensions)
	if err != nil {
		return nil, err
	}
	c.Reserved = g.Reserved
	k, rest, ok := ParsePublicKey(g.SignatureKey)
	if !ok || len(rest) > 0 {
		return nil, errors.New("ssh: signature key parse error")
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

func (s *openSSHCertSigner) Sign(rand io.Reader, data []byte) ([]byte, error) {
	return s.signer.Sign(rand, data)
}

func (s *openSSHCertSigner) PublicKey() PublicKey {
	return s.pub
}

// validateOpenSSHCertV01Signature uses the cert's SignatureKey to verify that
// the cert's Signature.Blob is the result of signing the cert bytes starting
// from the algorithm string and going up to and including the SignatureKey.
func validateOpenSSHCertV01Signature(cert *OpenSSHCertV01) bool {
	return cert.SignatureKey.Verify(cert.BytesForSigning(), cert.Signature.Blob)
}

// SignCert has an authority sign the certificate. It sets the
// Signature and SignatureKey of the cert.
func (c *OpenSSHCertV01) SignCert(authority Signer) error {
	pub := authority.PublicKey()
	c.SignatureKey = pub
	// Should get rand from some config?
	blob, err := authority.Sign(rand.Reader, c.BytesForSigning())
	if err != nil {
		return err
	}
	c.Signature = &signature{
		Format: pub.PrivateKeyAlgo(),
		Blob:   blob,
	}
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

func (cert *OpenSSHCertV01) BytesForSigning() []byte {
	c2 := *cert
	c2.Signature = nil
	out := MarshalPublicKey(&c2)
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
		SignatureKey:    MarshalPublicKey(c.SignatureKey),
	}
	if c.Signature != nil {
		generic.Signature = Marshal(*c.Signature)
	}
	genericBytes := Marshal(generic)

	prefix := Marshal(struct {
		Nonce []byte
		Key   []byte `ssh:"rest"`
	}{c.Nonce, c.Key.Marshal()})

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

func (c *OpenSSHCertV01) PrivateKeyAlgo() string {
	return c.Key.PrivateKeyAlgo()
}

func (c *OpenSSHCertV01) Verify(data []byte, sig []byte) bool {
	return c.Key.Verify(data, sig)
}

func parseSignatureBody(in []byte) (out *signature, rest []byte, ok bool) {
	var format []byte
	if format, in, ok = parseString(in); !ok {
		return
	}

	out = &signature{
		Format: string(format),
	}

	if out.Blob, in, ok = parseString(in); !ok {
		return
	}

	return out, in, ok
}

func parseSignature(in []byte) (out *signature, rest []byte, ok bool) {
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
