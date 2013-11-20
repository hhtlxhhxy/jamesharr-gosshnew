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
	KeyboardInteractiveCallback func(conn ConnMetadata, client ClientKeyboardInteractive) bool
}

// AddHostKey adds a private key as a host key. If an existing host
// key exists with the same algorithm, it is overwritten.
func (s *ServerConfig) AddHostKey(key Signer) {
	for i, k := range s.hostKeys {
		if k.PublicKey().PublicKeyAlgo() == key.PublicKey().PublicKeyAlgo() {
			s.hostKeys[i] = key
			return
		}
	}

	s.hostKeys = append(s.hostKeys, key)
}

// SetRSAPrivateKey sets the private key for a Server. A Server must have a
// private key configured in order to accept connections. The private key must
// be in the form of a PEM encoded, PKCS#1, RSA private key. The file "id_rsa"
// typically contains such a key.
func (s *ServerConfig) SetRSAPrivateKey(pemBytes []byte) error {
	priv, err := ParsePrivateKey(pemBytes)
	if err != nil {
		return err
	}
	s.AddHostKey(priv)
	return nil
}

// cachedPubKey contains the results of querying whether a public key is
// acceptable for a user. The cache only applies to a single ServerConn.
type cachedPubKey struct {
	user, algo string
	pubKey     []byte
	result     bool
}

const maxCachedPubKeys = 16

// A ServerConn represents an incoming connection.
type ServerConn struct {
	transport *handshakeTransport
	config    ServerConfig
	sshConn

	// cachedPubKeys contains the cache results of tests for public keys.
	// Since SSH clients will query whether a public key is acceptable
	// before attempting to authenticate with it, we end up with duplicate
	// queries for public key validity.
	cachedPubKeys []cachedPubKey

	// The connection protocol.
	mux *mux
}

// Server returns a new SSH server connection
// using c as the underlying transport.
func Server(c net.Conn, config *ServerConfig) *ServerConn {
	s := &ServerConn{
		sshConn: sshConn{conn: c},
		config:  *config,
	}
	s.config.setDefaults()
	return s
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

// Handshake performs an SSH transport and client authentication on the given ServerConn.
func (s *ServerConn) Handshake() error {
	if len(s.config.hostKeys) == 0 {
		return errors.New("ssh: server has no host keys")
	}

	var err error
	s.serverVersion = []byte(packageVersion)
	s.clientVersion, err = exchangeVersions(s.sshConn.conn, s.serverVersion)
	if err != nil {
		return err
	}

	tr := newTransport(s.sshConn.conn, s.config.Rand, false /* not client */)
	s.transport = newServerTransport(tr, s.clientVersion, s.serverVersion, &s.config)

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
	if err = unmarshal(&serviceRequest, packet, msgServiceRequest); err != nil {
		return err
	}
	if serviceRequest.Service != serviceUserAuth {
		return errors.New("ssh: requested service '" + serviceRequest.Service + "' before authenticating")
	}
	serviceAccept := serviceAcceptMsg{
		Service: serviceUserAuth,
	}
	if err := s.transport.writePacket(marshal(msgServiceAccept, serviceAccept)); err != nil {
		return err
	}

	if err := s.authenticate(); err != nil {
		return err
	}
	s.mux = newMux(s.transport)
	go s.handleGlobalRequests()
	go s.mux.Loop()

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

func (s *ServerConn) handleGlobalRequests() {
	for r := range s.mux.incomingRequests {
		if r.WantReply {
			s.mux.AckRequest(false, nil)
		}
	}
}

// testPubKey returns true if the given public key is acceptable for the user.
func (s *ServerConn) testPubKey(algo string, pubKey []byte) bool {
	if s.config.PublicKeyCallback == nil || !isAcceptableAlgo(algo) {
		return false
	}

	for _, c := range s.cachedPubKeys {
		if c.user == s.user && c.algo == algo && bytes.Equal(c.pubKey, pubKey) {
			return c.result
		}
	}

	result := s.config.PublicKeyCallback(s, algo, pubKey)
	if len(s.cachedPubKeys) < maxCachedPubKeys {
		c := cachedPubKey{
			user:   s.user,
			algo:   algo,
			pubKey: make([]byte, len(pubKey)),
			result: result,
		}
		copy(c.pubKey, pubKey)
		s.cachedPubKeys = append(s.cachedPubKeys, c)
	}

	return result
}

func (s *ServerConn) authenticate() error {
	var userAuthReq userAuthRequestMsg
	var err error
	var packet []byte

userAuthLoop:
	for {
		if packet, err = s.transport.readPacket(); err != nil {
			return err
		}
		if err = unmarshal(&userAuthReq, packet, msgUserAuthRequest); err != nil {
			return err
		}

		if userAuthReq.Service != serviceSSH {
			return errors.New("ssh: client attempted to negotiate for unknown service: " + userAuthReq.Service)
		}

		s.user = userAuthReq.User
		switch userAuthReq.Method {
		case "none":
			if s.config.NoClientAuth {
				s.user = ""
				break userAuthLoop
			}
		case "password":
			if s.config.PasswordCallback == nil {
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

			if s.config.PasswordCallback(s, password) {
				break userAuthLoop
			}
		case "keyboard-interactive":
			if s.config.KeyboardInteractiveCallback == nil {
				break
			}

			if s.config.KeyboardInteractiveCallback(s, &sshClientKeyboardInteractive{s}) {
				break userAuthLoop
			}
		case "publickey":
			if s.config.PublicKeyCallback == nil {
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

			pubKey, payload, ok := parseString(payload)
			if !ok {
				return ParseError{msgUserAuthRequest}
			}
			if isQuery {
				// The client can query if the given public key
				// would be okay.
				if len(payload) > 0 {
					return ParseError{msgUserAuthRequest}
				}
				if s.testPubKey(algo, pubKey) {
					okMsg := userAuthPubKeyOkMsg{
						Algo:   algo,
						PubKey: string(pubKey),
					}
					if err = s.transport.writePacket(marshal(msgUserAuthPubKeyOk, okMsg)); err != nil {
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
				if !isAcceptableAlgo(algo) || !isAcceptableAlgo(sig.Format) || pubAlgoToPrivAlgo(algo) != sig.Format {
					break
				}
				signedData := buildDataSignedForAuth(s.transport.getSessionID(), userAuthReq, algoBytes, pubKey)
				key, _, ok := ParsePublicKey(pubKey)
				if !ok {
					return ParseError{msgUserAuthRequest}
				}

				if !key.Verify(signedData, sig.Blob) {
					return errors.New("ssh: signature verification failed")
				}
				// TODO(jmpittman): Implement full validation for certificates.
				if s.testPubKey(algo, pubKey) {
					break userAuthLoop
				}
			}
		}

		var failureMsg userAuthFailureMsg
		if s.config.PasswordCallback != nil {
			failureMsg.Methods = append(failureMsg.Methods, "password")
		}
		if s.config.PublicKeyCallback != nil {
			failureMsg.Methods = append(failureMsg.Methods, "publickey")
		}
		if s.config.KeyboardInteractiveCallback != nil {
			failureMsg.Methods = append(failureMsg.Methods, "keyboard-interactive")
		}

		if len(failureMsg.Methods) == 0 {
			return errors.New("ssh: no authentication methods configured but NoClientAuth is also false")
		}

		if err = s.transport.writePacket(marshal(msgUserAuthFailure, failureMsg)); err != nil {
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
	*ServerConn
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

	if err := c.transport.writePacket(marshal(msgUserAuthInfoRequest, userAuthInfoRequestMsg{
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

// Accept reads and processes messages on a ServerConn. It must be called
// in order to demultiplex messages to any resulting Channels.
func (s *ServerConn) Accept() (NewChannel, error) {
	in, ok := <-s.mux.incomingChannels
	if !ok {
		return nil, io.EOF
	}
	return in, nil
}

// A Listener implements a network listener (net.Listener) for SSH connections.
type Listener struct {
	listener net.Listener
	config   *ServerConfig
}

// Addr returns the listener's network address.
func (l *Listener) Addr() net.Addr {
	return l.listener.Addr()
}

// Close closes the listener.
func (l *Listener) Close() error {
	return l.listener.Close()
}

// Accept waits for and returns the next incoming SSH connection.
// The receiver should call Handshake() in another goroutine
// to avoid blocking the accepter.
func (l *Listener) Accept() (*ServerConn, error) {
	c, err := l.listener.Accept()
	if err != nil {
		return nil, err
	}
	return Server(c, l.config), nil
}

// Listen creates an SSH listener accepting connections on
// the given network address using net.Listen.
func Listen(network, addr string, config *ServerConfig) (*Listener, error) {
	l, err := net.Listen(network, addr)
	if err != nil {
		return nil, err
	}
	return &Listener{
		l,
		config,
	}, nil
}
