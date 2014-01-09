// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"bytes"
	"errors"
	"io"
	"net"

	_ "crypto/sha1"
)

type ServerConfig struct {
	// Shared configuration.
	Config

	hostKeys []Signer

	// NoClientAuth is true if clients are allowed to connect without
	// authenticating.
	NoClientAuth bool

	// PasswordCallback, if non-nil, is called when a user attempts to
	// authenticate using a password. It may be called concurrently from
	// several goroutines.
	PasswordCallback func(conn ConnMetadata, password []byte) bool

	// PublicKeyCallback, if non-nil, is called when a client attempts public
	// key authentication. It must return true if the given public key is
	// valid for the given user.
	PublicKeyCallback func(conn ConnMetadata, algo string, pubkey []byte) bool

	// KeyboardInteractiveCallback, if non-nil, is called when
	// keyboard-interactive authentication is selected (RFC
	// 4256). The client object's Challenge function should be
	// used to query the user. The callback may offer multiple
	// Challenge rounds. To avoid information leaks, the client
	// should be presented a challenge even if the user is
	// unknown.
	KeyboardInteractiveCallback func(conn ConnMetadata, client KeyboardInteractiveChallenge) bool
}

// AddHostKey adds a private key as a host key. If an existing host
// key exists with the same algorithm, it is overwritten. Each server
// config must have at least one host key.
func (s *ServerConfig) AddHostKey(key Signer) {
	for i, k := range s.hostKeys {
		if k.PublicKey().PublicKeyAlgo() == key.PublicKey().PublicKeyAlgo() {
			s.hostKeys[i] = key
			return
		}
	}

	s.hostKeys = append(s.hostKeys, key)
}

// cachedPubKey contains the results of querying whether a public key is
// acceptable for a user.
type cachedPubKey struct {
	user, algo string
	pubKey     []byte
	result     bool
}

func (k1 *cachedPubKey) Equal(k2 *cachedPubKey) bool {
	return k1.user == k2.user && k1.algo == k2.algo && bytes.Equal(k1.pubKey, k2.pubKey)
}

const maxCachedPubKeys = 16

// pubKeyCache caches tests for public keys.  Since SSH clients
// will query whether a public key is acceptable before attempting to
// authenticate with it, we end up with duplicate queries for public
// key validity.  The cache only applies to a single ServerConn.
type pubKeyCache struct {
	keys []cachedPubKey
}

// get returns the result for a given user/algo/key tuple.
func (c *pubKeyCache) get(candidate cachedPubKey) (result bool, ok bool) {
	for _, k := range c.keys {
		if k.Equal(&candidate) {
			return k.result, true
		}
	}
	return false, false
}

// add adds the given tuple to the cache.
func (c *pubKeyCache) add(candidate cachedPubKey) {
	if len(c.keys) < maxCachedPubKeys {
		c.keys = append(c.keys, candidate)
	}
}

// TODO(hanwen): should this be an interface or a struct?

// ServerConn is an authenticated SSH connection, as seen from the
// server
type ServerConn struct {
	Conn

	// TODO(hanwen): add permission data here.
}

// NewServerConn starts a new SSH server with c as the underlying
// transport.  It starts with a handshake, and if the handshake is
// unsuccessful, it closes the connection and returns an error.  The
// Request and NewChannel channels must be serviced, or the connection
// will hang.
func NewServerConn(c net.Conn, config *ServerConfig) (*ServerConn, <-chan NewChannel, <-chan *Request, error) {
	fullConf := *config
	fullConf.setDefaults()
	s := &connection{
		sshConn: sshConn{conn: c},
	}
	if err := s.serverHandshake(&fullConf); err != nil {
		c.Close()
		return nil, nil, nil, err
	}
	return &ServerConn{s}, s.mux.incomingChannels, s.mux.incomingRequests, nil
}

// signAndMarshal signs the data with the appropriate algorithm,
// and serializes the result in SSH wire format.
func signAndMarshal(k Signer, rand io.Reader, data []byte) ([]byte, error) {
	sig, err := k.Sign(rand, data)
	if err != nil {
		return nil, err
	}

	return serializeSignature(k.PublicKey().PrivateKeyAlgo(), sig), nil
}

// handshake performs key exchange and user authentication.
func (s *connection) serverHandshake(config *ServerConfig) error {
	if len(config.hostKeys) == 0 {
		return errors.New("ssh: server has no host keys")
	}

	var err error
	s.serverVersion = []byte(packageVersion)
	s.clientVersion, err = exchangeVersions(s.sshConn.conn, s.serverVersion)
	if err != nil {
		return err
	}

	tr := newTransport(s.sshConn.conn, config.Rand, false /* not client */)
	s.transport = newServerTransport(tr, s.clientVersion, s.serverVersion, config)

	if err := s.transport.requestKeyChange(); err != nil {
		return err
	}

	if packet, err := s.transport.readPacket(); err != nil {
		return err
	} else if packet[0] != msgNewKeys {
		return UnexpectedMessageError{msgNewKeys, packet[0]}
	}

	var packet []byte
	if packet, err = s.transport.readPacket(); err != nil {
		return err
	}

	var serviceRequest serviceRequestMsg
	if err = Unmarshal(packet, &serviceRequest); err != nil {
		return err
	}
	if serviceRequest.Service != serviceUserAuth {
		return errors.New("ssh: requested service '" + serviceRequest.Service + "' before authenticating")
	}
	serviceAccept := serviceAcceptMsg{
		Service: serviceUserAuth,
	}
	if err := s.transport.writePacket(Marshal(serviceAccept)); err != nil {
		return err
	}

	if err := s.serverAuthenticate(config); err != nil {
		return err
	}
	s.mux = newMux(s.transport)
	return err
}

func isAcceptableAlgo(algo string) bool {
	switch algo {
	case KeyAlgoRSA, KeyAlgoDSA, KeyAlgoECDSA256, KeyAlgoECDSA384, KeyAlgoECDSA521,
		CertAlgoRSAv01, CertAlgoDSAv01, CertAlgoECDSA256v01, CertAlgoECDSA384v01, CertAlgoECDSA521v01:
		return true
	}
	return false
}

func (s *connection) serverAuthenticate(config *ServerConfig) error {
	var userAuthReq userAuthRequestMsg
	var err error
	var packet []byte
	var cache pubKeyCache

userAuthLoop:
	for {
		if packet, err = s.transport.readPacket(); err != nil {
			return err
		}
		if err = Unmarshal(packet, &userAuthReq); err != nil {
			return err
		}

		if userAuthReq.Service != serviceSSH {
			return errors.New("ssh: client attempted to negotiate for unknown service: " + userAuthReq.Service)
		}

		s.user = userAuthReq.User
		switch userAuthReq.Method {
		case "none":
			if config.NoClientAuth {
				s.user = ""
				break userAuthLoop
			}
		case "password":
			if config.PasswordCallback == nil {
				break
			}
			payload := userAuthReq.Payload
			if len(payload) < 1 || payload[0] != 0 {
				return ParseError{msgUserAuthRequest}
			}
			payload = payload[1:]
			password, payload, ok := parseString(payload)
			if !ok || len(payload) > 0 {
				return ParseError{msgUserAuthRequest}
			}

			if config.PasswordCallback(s, password) {
				break userAuthLoop
			}
		case "keyboard-interactive":
			if config.KeyboardInteractiveCallback == nil {
				break
			}

			prompter := &sshClientKeyboardInteractive{s}
			if config.KeyboardInteractiveCallback(s, prompter.Challenge) {
				break userAuthLoop
			}
		case "publickey":
			if config.PublicKeyCallback == nil {
				break
			}
			payload := userAuthReq.Payload
			if len(payload) < 1 {
				return ParseError{msgUserAuthRequest}
			}
			isQuery := payload[0] == 0
			payload = payload[1:]
			algoBytes, payload, ok := parseString(payload)
			if !ok {
				return ParseError{msgUserAuthRequest}
			}
			algo := string(algoBytes)
			if !isAcceptableAlgo(algo) {
				break
			}

			pubKey, payload, ok := parseString(payload)
			if !ok {
				return ParseError{msgUserAuthRequest}
			}

			candidate := cachedPubKey{
				user:   s.user,
				algo:   algo,
				pubKey: pubKey,
			}
			candidate.result, ok = cache.get(candidate)
			if !ok {
				candidate.result = config.PublicKeyCallback(s, candidate.algo, candidate.pubKey)
				cache.add(candidate)
			}

			if isQuery {
				// The client can query if the given public key
				// would be okay.
				if len(payload) > 0 {
					return ParseError{msgUserAuthRequest}
				}

				if candidate.result {
					okMsg := userAuthPubKeyOkMsg{
						Algo:   algo,
						PubKey: string(pubKey),
					}
					if err = s.transport.writePacket(Marshal(okMsg)); err != nil {
						return err
					}
					continue userAuthLoop
				}
			} else {
				sig, payload, ok := parseSignature(payload)
				if !ok || len(payload) > 0 {
					return ParseError{msgUserAuthRequest}
				}
				// Ensure the public key algo and signature algo
				// are supported.  Compare the private key
				// algorithm name that corresponds to algo with
				// sig.Format.  This is usually the same, but
				// for certs, the names differ.
				if !isAcceptableAlgo(sig.Format) || pubAlgoToPrivAlgo(algo) != sig.Format {
					break
				}
				signedData := buildDataSignedForAuth(s.transport.getSessionID(), userAuthReq, algoBytes, pubKey)
				key, _, err := ParsePublicKey(pubKey)
				if err != nil {
					return err
				}

				if !key.Verify(signedData, sig.Blob) {
					return errors.New("ssh: signature verification failed")
				}

				// TODO(jmpittman): Implement full validation for certificates.
				if candidate.result {
					break userAuthLoop
				}
			}
		}

		var failureMsg userAuthFailureMsg
		if config.PasswordCallback != nil {
			failureMsg.Methods = append(failureMsg.Methods, "password")
		}
		if config.PublicKeyCallback != nil {
			failureMsg.Methods = append(failureMsg.Methods, "publickey")
		}
		if config.KeyboardInteractiveCallback != nil {
			failureMsg.Methods = append(failureMsg.Methods, "keyboard-interactive")
		}

		if len(failureMsg.Methods) == 0 {
			return errors.New("ssh: no authentication methods configured but NoClientAuth is also false")
		}

		if err = s.transport.writePacket(Marshal(failureMsg)); err != nil {
			return err
		}
	}

	packet = []byte{msgUserAuthSuccess}
	if err = s.transport.writePacket(packet); err != nil {
		return err
	}

	return nil
}

// sshClientKeyboardInteractive implements a ClientKeyboardInteractive by
// asking the client on the other side of a ServerConn.
type sshClientKeyboardInteractive struct {
	*connection
}

func (c *sshClientKeyboardInteractive) Challenge(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
	if len(questions) != len(echos) {
		return nil, errors.New("ssh: echos and questions must have equal length")
	}

	var prompts []byte
	for i := range questions {
		prompts = appendString(prompts, questions[i])
		prompts = appendBool(prompts, echos[i])
	}

	if err := c.transport.writePacket(Marshal(userAuthInfoRequestMsg{
		Instruction: instruction,
		NumPrompts:  uint32(len(questions)),
		Prompts:     prompts,
	})); err != nil {
		return nil, err
	}

	packet, err := c.transport.readPacket()
	if err != nil {
		return nil, err
	}
	if packet[0] != msgUserAuthInfoResponse {
		return nil, UnexpectedMessageError{msgUserAuthInfoResponse, packet[0]}
	}
	packet = packet[1:]

	n, packet, ok := parseUint32(packet)
	if !ok || int(n) != len(questions) {
		return nil, &ParseError{msgUserAuthInfoResponse}
	}

	for i := uint32(0); i < n; i++ {
		ans, rest, ok := parseString(packet)
		if !ok {
			return nil, &ParseError{msgUserAuthInfoResponse}
		}

		answers = append(answers, string(ans))
		packet = rest
	}
	if len(packet) != 0 {
		return nil, errors.New("ssh: junk at end of message")
	}

	return answers, nil
}
