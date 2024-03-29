// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"errors"
	"fmt"
	"net"
)

// Client implements a traditional SSH client supporting shells,
// subprocesses, port forwarding and tunneled dialing.
type Client struct {
	Conn
	forwardList // forwarded tcpip connections from the remote side
}

// NewClient creates a Client on top of the given connection.
func NewClient(c Conn, chans <-chan NewChannel, reqs <-chan *Request) *Client {
	conn := &Client{
		Conn: c,
	}

	go conn.handleGlobalRequests(reqs)
	go conn.handleChannelOpens(chans)
	go func() {
		conn.Wait()
		conn.forwardList.closeAll()
	}()
	return conn
}

// NewClientConn establishes an authenticated SSH connection using c
// as the underlying transport.  The Request and NewChannel channels
// must be serviced, or the connection will hang.
func NewClientConn(c net.Conn, addr string, config *ClientConfig) (Conn, <-chan NewChannel, <-chan *Request, error) {
	fullConf := *config
	fullConf.setDefaults()
	conn := &connection{
		sshConn: sshConn{conn: c},
	}

	if err := conn.clientHandshake(addr, &fullConf); err != nil {
		c.Close()
		return nil, nil, nil, fmt.Errorf("ssh: handshake failed: %v", err)
	}
	conn.mux = newMux(conn.transport)
	return conn, conn.mux.incomingChannels, conn.mux.incomingRequests, nil
}

// handshake performs the client side key exchange. See RFC 4253 Section 7.
func (c *connection) clientHandshake(dialAddress string, config *ClientConfig) error {
	c.clientVersion = []byte(packageVersion)
	if config.ClientVersion != "" {
		c.clientVersion = []byte(config.ClientVersion)
	}

	var err error
	c.serverVersion, err = exchangeVersions(c.sshConn.conn, c.clientVersion)
	if err != nil {
		return err
	}

	c.transport = newClientTransport(
		newTransport(c.sshConn.conn, config.Rand, true /* is client */),
		c.clientVersion, c.serverVersion, config, dialAddress, c.sshConn.RemoteAddr())
	if err := c.transport.requestKeyChange(); err != nil {
		return err
	}

	if packet, err := c.transport.readPacket(); err != nil {
		return err
	} else if packet[0] != msgNewKeys {
		return UnexpectedMessageError{msgNewKeys, packet[0]}
	}
	return c.clientAuthenticate(config)
}

// verifyHostKeySignature verifies the host key obtained in the key
// exchange.
func verifyHostKeySignature(hostKeyAlgo string, result *kexResult) error {
	hostKey, err := ParsePublicKey(result.HostKey)
	if err != nil {
		return err
	}

	sig, rest, ok := parseSignatureBody(result.Signature)
	if len(rest) > 0 || !ok {
		return errors.New("ssh: signature parse error")
	}

	if !hostKey.Verify(result.H, sig) {
		return errors.New("ssh: host key signature error")
	}
	return nil
}

// NewSession opens a new Session for this client.
func (c *Client) NewSession() (*Session, error) {
	ch, in, err := c.OpenChannel("session", nil)
	if err != nil {
		return nil, err
	}
	return newSession(ch, in)
}

func (c *Client) handleGlobalRequests(incoming <-chan *Request) {
	for r := range incoming {
		// This handles keepalive messages and matches
		// the behaviour of OpenSSH.
		r.Reply(false, nil)
	}
}

// Handle channel open messages from the remote side.
func (c *Client) handleChannelOpens(in <-chan NewChannel) {
	for ch := range in {
		c.handleChannelOpen(ch)
	}
}

func (c *Client) handleChannelOpen(newCh NewChannel) {
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

// Dial starts a client connecting to the given SSH server. It is a
// convenience function that connects to the given network address,
// initiates the SSH handshake, and then sets up a Client.
func Dial(network, addr string, config *ClientConfig) (*Client, error) {
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	c, chans, reqs, err := NewClientConn(conn, addr, config)
	if err != nil {
		return nil, err
	}
	return NewClient(c, chans, reqs), nil
}

// A ClientConfig structure is used to configure a Client. After one has
// been passed to an SSH function it must not be modified.
type ClientConfig struct {
	// Shared configuration.
	Config

	// The username to authenticate.
	User string

	// A slice of AuthMethod instances. Only the first
	// instance of a particular RFC 4252 method will be used
	// during authentication.
	Auth []AuthMethod

	// HostKeyChecker, if not nil, is called during the cryptographic
	// handshake to validate the server's host key. A nil HostKeyChecker
	// implies that all host keys are accepted.
	HostKeyChecker HostKeyChecker

	// The identification string that will be used for the connection.
	// If empty, a reasonable default is used.
	ClientVersion string
}
