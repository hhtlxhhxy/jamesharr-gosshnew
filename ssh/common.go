// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"crypto"
	"crypto/rand"
	"fmt"
	"io"
	"sync"

	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
)

// These are string constants in the SSH protocol.
const (
	compressionNone = "none"
	serviceUserAuth = "ssh-userauth"
	serviceSSH      = "ssh-connection"
)

var supportedKexAlgos = []string{
	kexAlgoECDH256, kexAlgoECDH384, kexAlgoECDH521,
	kexAlgoDH14SHA1, kexAlgoDH1SHA1,
}

var supportedHostKeyAlgos = []string{
	KeyAlgoECDSA256, KeyAlgoECDSA384, KeyAlgoECDSA521,
	KeyAlgoRSA, KeyAlgoDSA,
}

var supportedCompressions = []string{compressionNone}

// hashFuncs keeps the mapping of supported algorithms to their respective
// hashes needed for signature verification.
var hashFuncs = map[string]crypto.Hash{
	KeyAlgoRSA:          crypto.SHA1,
	KeyAlgoDSA:          crypto.SHA1,
	KeyAlgoECDSA256:     crypto.SHA256,
	KeyAlgoECDSA384:     crypto.SHA384,
	KeyAlgoECDSA521:     crypto.SHA512,
	CertAlgoRSAv01:      crypto.SHA1,
	CertAlgoDSAv01:      crypto.SHA1,
	CertAlgoECDSA256v01: crypto.SHA256,
	CertAlgoECDSA384v01: crypto.SHA384,
	CertAlgoECDSA521v01: crypto.SHA512,
}

// UnexpectedMessageError results when the SSH message that we received didn't
// match what we wanted.
type UnexpectedMessageError struct {
	Expected, Got uint8
}

func (u UnexpectedMessageError) Error() string {
	return fmt.Sprintf("ssh: unexpected message type %d (expected %d)", u.Got, u.Expected)
}

// ParseError results from a malformed SSH message.
type ParseError struct {
	Type uint8
}

func (p ParseError) Error() string {
	return fmt.Sprintf("ssh: parse error in message type %d", p.Type)
}

func findCommonAlgorithm(clientAlgos []string, serverAlgos []string) (commonAlgo string, ok bool) {
	for _, clientAlgo := range clientAlgos {
		for _, serverAlgo := range serverAlgos {
			if clientAlgo == serverAlgo {
				return clientAlgo, true
			}
		}
	}
	return
}

func findCommonCipher(clientCiphers []string, serverCiphers []string) (commonCipher string, ok bool) {
	for _, clientCipher := range clientCiphers {
		for _, serverCipher := range serverCiphers {
			// reject the cipher if we have no cipherModes definition
			if clientCipher == serverCipher && cipherModes[clientCipher] != nil {
				return clientCipher, true
			}
		}
	}
	return
}

type algorithms struct {
	kex          string
	hostKey      string
	wCipher      string
	rCipher      string
	rMAC         string
	wMAC         string
	rCompression string
	wCompression string
}

func findAgreedAlgorithms(clientKexInit, serverKexInit *kexInitMsg) (algs *algorithms) {
	var ok bool
	result := &algorithms{}
	result.kex, ok = findCommonAlgorithm(clientKexInit.KexAlgos, serverKexInit.KexAlgos)
	if !ok {
		return
	}

	result.hostKey, ok = findCommonAlgorithm(clientKexInit.ServerHostKeyAlgos, serverKexInit.ServerHostKeyAlgos)
	if !ok {
		return
	}

	result.wCipher, ok = findCommonCipher(clientKexInit.CiphersClientServer, serverKexInit.CiphersClientServer)
	if !ok {
		return
	}

	result.rCipher, ok = findCommonCipher(clientKexInit.CiphersServerClient, serverKexInit.CiphersServerClient)
	if !ok {
		return
	}

	result.wMAC, ok = findCommonAlgorithm(clientKexInit.MACsClientServer, serverKexInit.MACsClientServer)
	if !ok {
		return
	}

	result.rMAC, ok = findCommonAlgorithm(clientKexInit.MACsServerClient, serverKexInit.MACsServerClient)
	if !ok {
		return
	}

	result.wCompression, ok = findCommonAlgorithm(clientKexInit.CompressionClientServer, serverKexInit.CompressionClientServer)
	if !ok {
		return
	}

	result.rCompression, ok = findCommonAlgorithm(clientKexInit.CompressionServerClient, serverKexInit.CompressionServerClient)
	if !ok {
		return
	}

	return result
}

// If rekeythreshold is too small, we can't make any progress sending
// stuff.
const minRekeyThreshold uint64 = 256

// Config contains configuration data common to both ServerConfig and
// ClientConfig.
type Config struct {
	// Rand provides the source of entropy for cryptographic
	// primitives. If Rand is nil, the cryptographic random reader
	// in package crypto/rand will be used.
	Rand io.Reader

	// The maximum number of bytes sent or received after which a
	// new key is negotiated. It must be at least 256. If
	// unspecified, 1 gigabyte is used.
	RekeyThreshold uint64

	// The allowed key exchanges algorithms. If unspecified then a
	// default set of algorithms is used.
	KeyExchanges []string

	// The allowed cipher algorithms. If unspecified then DefaultCipherOrder is
	// used.
	Ciphers []string

	// The allowed MAC algorithms. If unspecified then DefaultMACOrder is used.
	MACs []string
}

// setDefaults sets sensible values for unset fields in config.
func (c *Config) setDefaults() {
	if c.Rand == nil {
		c.Rand = rand.Reader
	}
	if c.Ciphers == nil {
		c.Ciphers = DefaultCipherOrder
	}

	if c.KeyExchanges == nil {
		c.KeyExchanges = defaultKeyExchangeOrder
	}

	if c.MACs == nil {
		c.MACs = DefaultMACOrder
	}
	if c.RekeyThreshold == 0 {
		// RFC 4253, section 9 suggests rekeying after 1G.
		c.RekeyThreshold = 1 << 30
	}
	if c.RekeyThreshold < minRekeyThreshold {
		c.RekeyThreshold = minRekeyThreshold
	}
}

// buildDataSignedForAuth returns the data that is signed in order to prove
// possession of a private key. See RFC 4252, section 7.
func buildDataSignedForAuth(sessionId []byte, req userAuthRequestMsg, algo, pubKey []byte) []byte {
	user := []byte(req.User)
	service := []byte(req.Service)
	method := []byte(req.Method)

	length := stringLength(len(sessionId))
	length += 1
	length += stringLength(len(user))
	length += stringLength(len(service))
	length += stringLength(len(method))
	length += 1
	length += stringLength(len(algo))
	length += stringLength(len(pubKey))

	ret := make([]byte, length)
	r := marshalString(ret, sessionId)
	r[0] = msgUserAuthRequest
	r = r[1:]
	r = marshalString(r, user)
	r = marshalString(r, service)
	r = marshalString(r, method)
	r[0] = 1
	r = r[1:]
	r = marshalString(r, algo)
	r = marshalString(r, pubKey)
	return ret
}

// safeString sanitises s according to RFC 4251, section 9.2.
// All control characters except tab, carriage return and newline are
// replaced by 0x20.
func safeString(s string) string {
	out := []byte(s)
	for i, c := range out {
		if c < 0x20 && c != 0xd && c != 0xa && c != 0x9 {
			out[i] = 0x20
		}
	}
	return string(out)
}

func appendU16(buf []byte, n uint16) []byte {
	return append(buf, byte(n>>8), byte(n))
}

func appendU32(buf []byte, n uint32) []byte {
	return append(buf, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

func appendU64(buf []byte, n uint64) []byte {
	return append(buf,
		byte(n>>56), byte(n>>48), byte(n>>40), byte(n>>32),
		byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

func appendInt(buf []byte, n int) []byte {
	return appendU32(buf, uint32(n))
}

func appendString(buf []byte, s string) []byte {
	buf = appendU32(buf, uint32(len(s)))
	buf = append(buf, s...)
	return buf
}

func appendBool(buf []byte, b bool) []byte {
	if b {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}
	return buf
}

// newCond is a helper to hide the fact that there is no usable zero
// value for sync.Cond.
func newCond() *sync.Cond { return sync.NewCond(new(sync.Mutex)) }

// window represents the buffer available to clients
// wishing to write to a channel.
type window struct {
	*sync.Cond
	win          uint32 // RFC 4254 5.2 says the window size can grow to 2^32-1
	writeWaiters int
	closed       bool
}

// add adds win to the amount of window available
// for consumers.
func (w *window) add(win uint32) bool {
	// a zero sized window adjust is a noop.
	if win == 0 {
		return true
	}
	w.L.Lock()
	if w.win+win < win {
		w.L.Unlock()
		return false
	}
	w.win += win
	// It is unusual that multiple goroutines would be attempting to reserve
	// window space, but not guaranteed. Use broadcast to notify all waiters
	// that additional window is available.
	w.Broadcast()
	w.L.Unlock()
	return true
}

// close sets the window to closed, so all reservations fail
// immediately.
func (w *window) close() {
	w.L.Lock()
	w.closed = true
	w.Broadcast()
	w.L.Unlock()
}

// reserve reserves win from the available window capacity.
// If no capacity remains, reserve will block. reserve may
// return less than requested.
func (w *window) reserve(win uint32) (uint32, error) {
	var err error
	w.L.Lock()
	w.Broadcast()
	w.writeWaiters++
	for w.win == 0 && !w.closed {
		w.Wait()
	}
	w.writeWaiters--
	if w.win < win {
		win = w.win
	}
	w.win -= win
	if w.closed {
		err = io.EOF
	}
	w.L.Unlock()
	return win, err
}

// waitWriterBlocked waits until some goroutine is blocked for further
// writes. It is used in tests only.
func (w *window) waitWriterBlocked() {
	w.Cond.L.Lock()
	for w.writeWaiters == 0 {
		w.Cond.Wait()
	}
	w.Cond.L.Unlock()
}
