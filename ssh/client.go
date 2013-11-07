// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
)

// ClientConn represents the client side of an SSH connection.
type ClientConn struct {
	sshConn
	transport   rekeyingTransport
	config      *ClientConfig
	forwardList // forwarded tcpip connections from the remote side

	// Address as passed to the Dial function.
	dialAddress string

	serverVersion string
	mux           *mux
}

// Client returns a new SSH client connection using c as the underlying transport.
func Client(c net.Conn, config *ClientConfig) (*ClientConn, error) {
	return clientWithAddress(c, "", config)
}

func clientWithAddress(c net.Conn, addr string, config *ClientConfig) (*ClientConn, error) {
	conn := &ClientConn{
		sshConn:     sshConn{c, c},
		config:      config,
		dialAddress: addr,
	}

	if err := conn.handshake(); err != nil {
		return nil, fmt.Errorf("ssh: handshake failed: %v", err)
	}
	conn.mux = newMux(conn.transport)
	go conn.handleGlobalRequests(conn.mux.incomingRequests)
	go conn.handleChannelOpens(conn.mux.incomingChannels)
	go func() {
		conn.mux.Loop()
		conn.forwardList.closeAll()
	}()
	return conn, nil
}

// handshake performs the client side key exchange. See RFC 4253 Section 7.
func (c *ClientConn) handshake() error {
	clientVersion := []byte(packageVersion)
	if c.config.ClientVersion != "" {
		clientVersion = []byte(c.config.ClientVersion)
	}

	serverVersion, err := exchangeVersions(c.sshConn.conn, clientVersion)
	if err != nil {
		return err
	}
	c.serverVersion = string(serverVersion)

	c.transport = newClientTransport(
		newTransport(c.sshConn.conn, c.config.rand(), true /* is client */),
		clientVersion, serverVersion, c.config, c.dialAddress, c.sshConn.RemoteAddr())
	if err := c.transport.requestKeyChange(); err != nil {
		return err
	}

	if packet, err := c.transport.readPacket(); err != nil {
		return err
	} else if packet[0] != msgNewKeys {
		return UnexpectedMessageError{msgNewKeys, packet[0]}
	}
	return c.authenticate()
}

// verifyHostKeySignature verifies the host key obtained in the key
// exchange.
func verifyHostKeySignature(hostKeyAlgo string, result *kexResult) error {
	hostKey, rest, ok := ParsePublicKey(result.HostKey)
	if len(rest) > 0 || !ok {
		return errors.New("ssh: could not parse hostkey")
	}

	sig, rest, ok := parseSignatureBody(result.Signature)
	if len(rest) > 0 || !ok {
		return errors.New("ssh: signature parse error")
	}
	if sig.Format != hostKeyAlgo {
		return fmt.Errorf("ssh: got signature type %q, want %q", sig.Format, hostKeyAlgo)
	}

	if !hostKey.Verify(result.H, sig.Blob) {
		return errors.New("ssh: host key signature error")
	}
	return nil
}

func (c *ClientConn) handleGlobalRequests(incoming chan *ChannelRequest) {
	for r := range incoming {
		if r.WantReply {
			// This handles keepalive messages and matches
			// the behaviour of OpenSSH.
			c.mux.AckRequest(false, nil)
		}
	}
}

// Handle channel open messages from the remote side.
func (c *ClientConn) handleChannelOpens(in chan *channel) {
	for ch := range in {
		c.handleChannelOpen(ch)
	}
}

func (c *ClientConn) handleChannelOpen(ch *channel) {
	switch ch.ChannelType() {
	case "forwarded-tcpip":
		laddr, rest, ok := parseTCPAddr(ch.ExtraData())
		if !ok {
			// invalid request
			ch.Reject(ConnectionFailed, "could not parse TCP address")
			return
		}

		l, ok := c.forwardList.lookup(*laddr)
		if !ok {
			// Section 7.2, implementations MUST reject spurious incoming
			// connections.
			ch.Reject(Prohibited, "no forward for address")
			return
		}

		raddr, rest, ok := parseTCPAddr(rest)
		if !ok {
			// invalid request
			ch.Reject(ConnectionFailed, "could not parse TCP address")
			return
		}
		if err := ch.Accept(); err == nil {
			l <- forward{ch, raddr}
		}

	default:
		ch.Reject(UnknownChannelType, fmt.Sprintf("unknown channel type: %v", ch.ChannelType()))
	}
}

// parseTCPAddr parses the originating address from the remote into a *net.TCPAddr.
// RFC 4254 section 7.2 is mute on what to do if parsing fails but the forwardlist
// requires a valid *net.TCPAddr to operate, so we enforce that restriction here.
func parseTCPAddr(b []byte) (*net.TCPAddr, []byte, bool) {
	addr, b, ok := parseString(b)
	if !ok {
		return nil, b, false
	}
	port, b, ok := parseUint32(b)
	if !ok {
		return nil, b, false
	}
	ip := net.ParseIP(string(addr))
	if ip == nil {
		return nil, b, false
	}
	return &net.TCPAddr{IP: ip, Port: int(port)}, b, true
}

// Dial connects to the given network address using net.Dial and
// then initiates a SSH handshake, returning the resulting client connection.
func Dial(network, addr string, config *ClientConfig) (*ClientConn, error) {
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	return clientWithAddress(conn, addr, config)
}

// A ClientConfig structure is used to configure a ClientConn. After one has
// been passed to an SSH function it must not be modified.
type ClientConfig struct {
	// Rand provides the source of entropy for key exchange. If Rand is
	// nil, the cryptographic random reader in package crypto/rand will
	// be used.
	Rand io.Reader

	// The username to authenticate.
	User string

	// A slice of ClientAuth methods. Only the first instance
	// of a particular RFC 4252 method will be used during authentication.
	Auth []ClientAuth

	// HostKeyChecker, if not nil, is called during the cryptographic
	// handshake to validate the server's host key. A nil HostKeyChecker
	// implies that all host keys are accepted.
	HostKeyChecker HostKeyChecker

	// Cryptographic-related configuration.
	Crypto CryptoConfig

	// The identification string that will be used for the connection.
	// If empty, a reasonable default is used.
	ClientVersion string
}

func (c *ClientConfig) rand() io.Reader {
	if c.Rand == nil {
		return rand.Reader
	}
	return c.Rand
}
