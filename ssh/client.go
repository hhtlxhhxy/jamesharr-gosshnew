// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"errors"
	"fmt"
	"net"
)

// ClientConn represents the client side of an SSH connection.
type ClientConn struct {
	sshConn
	transport   rekeyingTransport
	config      *ClientConfig
	forwardList // forwarded tcpip connections from the remote side

	mux *mux
}

// Client returns a new SSH client connection using c as the underlying transport.
func Client(c net.Conn, config *ClientConfig) (*ClientConn, error) {
	return clientWithAddress(c, "", config)
}

func clientWithAddress(c net.Conn, addr string, config *ClientConfig) (*ClientConn, error) {
	fullConf := *config
	fullConf.setDefaults()
	conn := &ClientConn{
		sshConn: sshConn{conn: c},
		config:  &fullConf,
	}

	if err := conn.handshake(addr); err != nil {
		c.Close()
		return nil, fmt.Errorf("ssh: handshake failed: %v", err)
	}
	conn.mux = newMux(conn.transport)
	go conn.handleGlobalRequests(conn.mux.incomingRequests)
	go conn.handleChannelOpens(conn.mux.incomingChannels)
	go func() {
		conn.mux.Wait()
		conn.forwardList.closeAll()
	}()
	return conn, nil
}

// handshake performs the client side key exchange. See RFC 4253 Section 7.
func (c *ClientConn) handshake(dialAddr string) error {
	c.clientVersion = []byte(packageVersion)
	if c.config.ClientVersion != "" {
		c.clientVersion = []byte(c.config.ClientVersion)
	}

	var err error
	c.serverVersion, err = exchangeVersions(c.sshConn.conn, c.clientVersion)
	if err != nil {
		return err
	}

	c.transport = newClientTransport(
		newTransport(c.sshConn.conn, c.config.Rand, true /* is client */),
		c.clientVersion, c.serverVersion, c.config, dialAddr, c.sshConn.RemoteAddr())
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

func (c *ClientConn) handleGlobalRequests(incoming chan *Request) {
	for r := range incoming {
		// This handles keepalive messages and matches
		// the behaviour of OpenSSH.
		r.Reply(false, nil)
	}
}

// Handle channel open messages from the remote side.
func (c *ClientConn) handleChannelOpens(in chan NewChannel) {
	for ch := range in {
		c.handleChannelOpen(ch)
	}
}

func (c *ClientConn) handleChannelOpen(newCh NewChannel) {
	switch newCh.ChannelType() {
	case "forwarded-tcpip":
		laddr, rest, ok := parseTCPAddr(newCh.ExtraData())
		if !ok {
			// invalid request
			newCh.Reject(ConnectionFailed, "could not parse TCP address")
			return
		}

		l, ok := c.forwardList.lookup(*laddr)
		if !ok {
			// Section 7.2, implementations MUST reject spurious incoming
			// connections.
			newCh.Reject(Prohibited, "no forward for address")
			return
		}

		raddr, rest, ok := parseTCPAddr(rest)
		if !ok {
			// invalid request
			newCh.Reject(ConnectionFailed, "could not parse TCP address")
			return
		}

		if ch, incoming, err := newCh.Accept(); err == nil {
			go DiscardIncoming(incoming)
			l <- forward{ch, raddr}
		}

	default:
		newCh.Reject(UnknownChannelType, fmt.Sprintf("unknown channel type: %v", newCh.ChannelType()))
	}
}

// DiscardIncoming rejects all incoming requests.
func DiscardIncoming(in <-chan *Request) {
	for req := range in {
		if req.WantReply {
			req.Reply(false, nil)
		}
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
	// Shared configuration.
	Config

	// The username to authenticate.
	User string

	// A slice of ClientAuth methods. Only the first instance
	// of a particular RFC 4252 method will be used during authentication.
	Auth []ClientAuth

	// HostKeyChecker, if not nil, is called during the cryptographic
	// handshake to validate the server's host key. A nil HostKeyChecker
	// implies that all host keys are accepted.
	HostKeyChecker HostKeyChecker

	// The identification string that will be used for the connection.
	// If empty, a reasonable default is used.
	ClientVersion string
}
