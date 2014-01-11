package ssh

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

var (
	ecdsaKey    Signer
	ecdsa384Key Signer
	ecdsa521Key Signer
	testCertKey Signer
)

type testSigner struct {
	Signer
	pub PublicKey
}

func (ts *testSigner) PublicKey() PublicKey {
	if ts.pub != nil {
		return ts.pub
	}
	return ts.Signer.PublicKey()
}

func init() {
	raw256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecdsaKey, _ = NewSignerFromKey(raw256)

	raw384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ecdsa384Key, _ = NewSignerFromKey(raw384)

	raw521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	ecdsa521Key, _ = NewSignerFromKey(raw521)

	// Create a cert and sign it for use in tests.
	testCert := &OpenSSHCertV01{
		Nonce:           []byte{}, // To pass reflect.DeepEqual after marshal & parse, this must be non-nil
		Key:             ecdsaKey.PublicKey(),
		ValidPrincipals: []string{"gopher1", "gopher2"}, // increases test coverage
		ValidAfter:      0,                              // unix epoch
		ValidBefore:     CertTimeInfinity,               // The end of currently representable time.
		Reserved:        []byte{},                       // To pass reflect.DeepEqual after marshal & parse, this must be non-nil
		SignatureKey:    rsaKey.PublicKey(),
		CriticalOptions: map[string]string{},
		Extensions:      map[string]string{},
	}
	sig, _ := rsaKey.Sign(rand.Reader, testCert.BytesForSigning())
	testCert.Signature = sig
	testCertKey = &testSigner{
		Signer: ecdsaKey,
		pub:    testCert,
	}
}

func rawKey(pub PublicKey) interface{} {
	switch k := pub.(type) {
	case *rsaPublicKey:
		return (*rsa.PublicKey)(k)
	case *dsaPublicKey:
		return (*dsa.PublicKey)(k)
	case *ecdsaPublicKey:
		return (*ecdsa.PublicKey)(k)
	case *OpenSSHCertV01:
		return k
	}
	panic("unknown key type")
}

func TestKeyMarshalParse(t *testing.T) {
	keys := []Signer{rsaKey, dsaKey, ecdsaKey, ecdsa384Key, ecdsa521Key, testCertKey}
	for _, priv := range keys {
		pub := priv.PublicKey()
		roundtrip, err := ParsePublicKey(MarshalPublicKey(pub))
		if err != nil {
			t.Errorf("ParsePublicKey(%T): %v", pub, err)
		}

		k1 := rawKey(pub)
		k2 := rawKey(roundtrip)

		if !reflect.DeepEqual(k1, k2) {
			t.Errorf("got %#v in roundtrip, want %#v", k2, k1)
		}
	}
}

func TestUnsupportedCurves(t *testing.T) {
	raw, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	if _, err = NewSignerFromKey(raw); err == nil || !strings.Contains(err.Error(), "only P256") {
		t.Fatalf("NewPrivateKey should not succeed with P224, got: %v", err)
	}

	if _, err = NewPublicKey(&raw.PublicKey); err == nil || !strings.Contains(err.Error(), "only P256") {
		t.Fatalf("NewPublicKey should not succeed with P224, got: %v", err)
	}
}

func TestNewPublicKey(t *testing.T) {
	keys := []Signer{rsaKey, dsaKey, ecdsaKey}
	for _, k := range keys {
		raw := rawKey(k.PublicKey())
		pub, err := NewPublicKey(raw)
		if err != nil {
			t.Errorf("NewPublicKey(%#v): %v", raw, err)
		}
		if !reflect.DeepEqual(k.PublicKey(), pub) {
			t.Errorf("NewPublicKey(%#v) = %#v, want %#v", raw, pub, k.PublicKey())
		}
	}
}

func TestKeySignVerify(t *testing.T) {
	keys := []Signer{rsaKey, dsaKey, ecdsaKey, testCertKey}
	for _, priv := range keys {
		pub := priv.PublicKey()

		data := []byte("sign me")
		sig, err := priv.Sign(rand.Reader, data)
		if err != nil {
			t.Fatalf("Sign(%T): %v", priv, err)
		}

		if !pub.Verify(data, sig) {
			t.Errorf("publicKey.Verify(%T) failed", priv)
		}
	}
}

func TestParseRSAPrivateKey(t *testing.T) {
	key, err := ParsePrivateKey([]byte(testServerPrivateKey))
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}

	rsa, ok := key.(*rsaPrivateKey)
	if !ok {
		t.Fatalf("got %T, want *rsa.PrivateKey", rsa)
	}

	if err := rsa.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestParseECPrivateKey(t *testing.T) {
	// Taken from the data in test/ .
	pem := []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEINGWx0zo6fhJ/0EAfrPzVFyFC9s18lBt3cRoEDhS3ARooAoGCCqGSM49
AwEHoUQDQgAEi9Hdw6KvZcWxfg2IDhA7UkpDtzzt6ZqJXSsFdLd+Kx4S3Sx4cVO+
6/ZOXRnPmNAlLUqjShUsUBBngG0u2fqEqA==
-----END EC PRIVATE KEY-----`)

	key, err := ParsePrivateKey(pem)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}

	ecKey, ok := key.(*ecdsaPrivateKey)
	if !ok {
		t.Fatalf("got %T, want *ecdsaPrivateKey", ecKey)
	}

	if !validateECPublicKey(ecKey.Curve, ecKey.X, ecKey.Y) {
		t.Fatalf("public key does not validate.")
	}
}

// ssh-keygen -t dsa -f /tmp/idsa.pem
var dsaPEM = `-----BEGIN DSA PRIVATE KEY-----
MIIBuwIBAAKBgQD6PDSEyXiI9jfNs97WuM46MSDCYlOqWw80ajN16AohtBncs1YB
lHk//dQOvCYOsYaE+gNix2jtoRjwXhDsc25/IqQbU1ahb7mB8/rsaILRGIbA5WH3
EgFtJmXFovDz3if6F6TzvhFpHgJRmLYVR8cqsezL3hEZOvvs2iH7MorkxwIVAJHD
nD82+lxh2fb4PMsIiaXudAsBAoGAQRf7Q/iaPRn43ZquUhd6WwvirqUj+tkIu6eV
2nZWYmXLlqFQKEy4Tejl7Wkyzr2OSYvbXLzo7TNxLKoWor6ips0phYPPMyXld14r
juhT24CrhOzuLMhDduMDi032wDIZG4Y+K7ElU8Oufn8Sj5Wge8r6ANmmVgmFfynr
FhdYCngCgYEA3ucGJ93/Mx4q4eKRDxcWD3QzWyqpbRVRRV1Vmih9Ha/qC994nJFz
DQIdjxDIT2Rk2AGzMqFEB68Zc3O+Wcsmz5eWWzEwFxaTwOGWTyDqsDRLm3fD+QYj
nOwuxb0Kce+gWI8voWcqC9cyRm09jGzu2Ab3Bhtpg8JJ8L7gS3MRZK4CFEx4UAfY
Fmsr0W6fHB9nhS4/UXM8
-----END DSA PRIVATE KEY-----`

func TestParseDSA(t *testing.T) {
	s, err := ParsePrivateKey([]byte(dsaPEM))
	if err != nil {
		t.Fatalf("ParsePrivateKey returned error: %s", err)
	}

	data := []byte("sign me")
	sig, err := s.Sign(rand.Reader, data)
	if err != nil {
		t.Fatalf("dsa.Sign: %v", err)
	}

	if !s.PublicKey().Verify(data, sig) {
		t.Error("Verify failed.")
	}
}

// Tests for authorized_keys parsing.

// getTestKey returns a public key, and its base64 encoding.
func getTestKey() (PublicKey, string) {
	k := rsaKey.PublicKey()

	b := &bytes.Buffer{}
	e := base64.NewEncoder(base64.StdEncoding, b)
	e.Write(MarshalPublicKey(k))
	e.Close()

	return k, b.String()
}

func TestMarshalParsePublicKey(t *testing.T) {
	pub, pubSerialized := getTestKey()
	line := fmt.Sprintf("%s %s user@host", pub.PublicKeyAlgo(), pubSerialized)

	authKeys := MarshalAuthorizedKey(pub)
	actualFields := strings.Fields(string(authKeys))
	if len(actualFields) == 0 {
		t.Fatalf("failed authKeys: %v", authKeys)
	}

	// drop the comment
	expectedFields := strings.Fields(line)[0:2]

	if !reflect.DeepEqual(actualFields, expectedFields) {
		t.Errorf("got %v, expected %v", actualFields, expectedFields)
	}

	actPub, _, _, _, err := ParseAuthorizedKey([]byte(line))
	if err != nil {
		t.Fatalf("cannot parse %v: %v", line, err)
	}
	if !reflect.DeepEqual(actPub, pub) {
		t.Errorf("got %v, expected %v", actPub, pub)
	}
}

type authResult struct {
	pubKey   PublicKey
	options  []string
	comments string
	rest     string
	ok       bool
}

func testAuthorizedKeys(t *testing.T, authKeys []byte, expected []authResult) {
	rest := authKeys
	var values []authResult
	for len(rest) > 0 {
		var r authResult
		var err error
		r.pubKey, r.comments, r.options, rest, err = ParseAuthorizedKey(rest)
		r.ok = (err == nil)
		r.rest = string(rest)
		values = append(values, r)
	}

	if !reflect.DeepEqual(values, expected) {
		t.Errorf("got %v, expected %v", values, expected)
	}

}

func TestAuth(t *testing.T) {
	pub, pubSerialized := getTestKey()
	authWithOptions := []string{
		`# comments to ignore before any keys...`,
		``,
		`env="HOME=/home/root",no-port-forwarding ssh-rsa ` + pubSerialized + ` user@host`,
		`# comments to ignore, along with a blank line`,
		``,
		`env="HOME=/home/root2" ssh-rsa ` + pubSerialized + ` user2@host2`,
		``,
		`# more comments, plus a invalid entry`,
		`ssh-rsa data-that-will-not-parse user@host3`,
	}
	for _, eol := range []string{"\n", "\r\n"} {
		authOptions := strings.Join(authWithOptions, eol)
		rest2 := strings.Join(authWithOptions[3:], eol)
		rest3 := strings.Join(authWithOptions[6:], eol)
		testAuthorizedKeys(t, []byte(authOptions), []authResult{
			{pub, []string{`env="HOME=/home/root"`, "no-port-forwarding"}, "user@host", rest2, true},
			{pub, []string{`env="HOME=/home/root2"`}, "user2@host2", rest3, true},
			{nil, nil, "", "", false},
		})
	}
}

func TestAuthWithQuotedSpaceInEnv(t *testing.T) {
	pub, pubSerialized := getTestKey()
	authWithQuotedSpaceInEnv := []byte(`env="HOME=/home/root dir",no-port-forwarding ssh-rsa ` + pubSerialized + ` user@host`)
	testAuthorizedKeys(t, []byte(authWithQuotedSpaceInEnv), []authResult{
		{pub, []string{`env="HOME=/home/root dir"`, "no-port-forwarding"}, "user@host", "", true},
	})
}

func TestAuthWithQuotedCommaInEnv(t *testing.T) {
	pub, pubSerialized := getTestKey()
	authWithQuotedCommaInEnv := []byte(`env="HOME=/home/root,dir",no-port-forwarding ssh-rsa ` + pubSerialized + `   user@host`)
	testAuthorizedKeys(t, []byte(authWithQuotedCommaInEnv), []authResult{
		{pub, []string{`env="HOME=/home/root,dir"`, "no-port-forwarding"}, "user@host", "", true},
	})
}

func TestAuthWithQuotedQuoteInEnv(t *testing.T) {
	pub, pubSerialized := getTestKey()
	authWithQuotedQuoteInEnv := []byte(`env="HOME=/home/\"root dir",no-port-forwarding` + "\t" + `ssh-rsa` + "\t" + pubSerialized + `   user@host`)
	authWithDoubleQuotedQuote := []byte(`no-port-forwarding,env="HOME=/home/ \"root dir\"" ssh-rsa ` + pubSerialized + "\t" + `user@host`)
	testAuthorizedKeys(t, []byte(authWithQuotedQuoteInEnv), []authResult{
		{pub, []string{`env="HOME=/home/\"root dir"`, "no-port-forwarding"}, "user@host", "", true},
	})

	testAuthorizedKeys(t, []byte(authWithDoubleQuotedQuote), []authResult{
		{pub, []string{"no-port-forwarding", `env="HOME=/home/ \"root dir\""`}, "user@host", "", true},
	})
}

func TestAuthWithInvalidSpace(t *testing.T) {
	_, pubSerialized := getTestKey()
	authWithInvalidSpace := []byte(`env="HOME=/home/root dir", no-port-forwarding ssh-rsa ` + pubSerialized + ` user@host
#more to follow but still no valid keys`)
	testAuthorizedKeys(t, []byte(authWithInvalidSpace), []authResult{
		{nil, nil, "", "", false},
	})
}

func TestAuthWithMissingQuote(t *testing.T) {
	pub, pubSerialized := getTestKey()
	authWithMissingQuote := []byte(`env="HOME=/home/root,no-port-forwarding ssh-rsa ` + pubSerialized + ` user@host
env="HOME=/home/root",shared-control ssh-rsa ` + pubSerialized + ` user@host`)

	testAuthorizedKeys(t, []byte(authWithMissingQuote), []authResult{
		{pub, []string{`env="HOME=/home/root"`, `shared-control`}, "user@host", "", true},
	})
}

func TestInvalidEntry(t *testing.T) {
	authInvalid := []byte(`ssh-rsa`)
	_, _, _, _, err := ParseAuthorizedKey(authInvalid)
	if err == nil {
		t.Errorf("got valid entry for %q", authInvalid)
	}
}
