// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

// ClientConn represents the client side of an SSH connection.
type ClientConn struct {
	sshConn
	transport   rekeyingTransport
	config      *ClientConfig
	chanList    chanList // channels associated with this connection
	forwardList          // forwarded tcpip connections from the remote side
	globalRequest

	// Address as passed to the Dial function.
	dialAddress string

	serverVersion string
}

type globalRequest struct {
	sync.Mutex
	response chan interface{}
}

// Client returns a new SSH client connection using c as the underlying transport.
func Client(c net.Conn, config *ClientConfig) (*ClientConn, error) {
	return clientWithAddress(c, "", config)
}

func clientWithAddress(c net.Conn, addr string, config *ClientConfig) (*ClientConn, error) {
	conn := &ClientConn{
		config:        config,
		sshConn:       sshConn{c, c},
		globalRequest: globalRequest{response: make(chan interface{}, 1)},
		dialAddress:   addr,
	}

	if err := conn.handshake(); err != nil {
		return nil, fmt.Errorf("ssh: handshake failed: %v", err)
	}
	go conn.mainLoop()
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

// mainLoop reads incoming messages and routes channel messages
// to their respective ClientChans.
func (c *ClientConn) mainLoop() {
	defer func() {
		c.transport.Close()
		for _, ch := range c.chanList.dropAll() {
			ch.Close()
			close(ch.msg)
		}
		c.forwardList.closeAll()
	}()

	for {
		packet, err := c.transport.readPacket()
		if err != nil {
			break
		}
		// TODO(dfc) A note on blocking channel use.
		// The msg, data and dataExt channels of a clientChan can
		// cause this loop to block indefinitely if the consumer does
		// not service them.
		switch packet[0] {
		case msgChannelData:
			if len(packet) < 9 {
				// malformed data packet
				return
			}
			remoteId := binary.BigEndian.Uint32(packet[1:5])
			length := binary.BigEndian.Uint32(packet[5:9])
			packet = packet[9:]

			if length != uint32(len(packet)) {
				return
			}
			ch := c.chanList.getChan(remoteId)
			if ch == nil {
				return
			}
			ch.stdout.write(packet)
		case msgChannelExtendedData:
			if len(packet) < 13 {
				// malformed data packet
				return
			}
			remoteId := binary.BigEndian.Uint32(packet[1:5])
			datatype := binary.BigEndian.Uint32(packet[5:9])
			length := binary.BigEndian.Uint32(packet[9:13])
			packet = packet[13:]

			if length != uint32(len(packet)) {
				return
			}
			// RFC 4254 5.2 defines data_type_code 1 to be data destined
			// for stderr on interactive sessions. Other data types are
			// silently discarded.
			if datatype == 1 {
				ch := c.chanList.getChan(remoteId)
				if ch == nil {
					return
				}
				ch.stderr.write(packet)
			}

		case msgNewKeys:
			// A rekeying happened.
		default:
			decoded, err := decode(packet)
			if err != nil {
				if _, ok := err.(UnexpectedMessageError); ok {
					fmt.Printf("mainLoop: unexpected message: %v\n", err)
					continue
				}
				return
			}
			switch msg := decoded.(type) {
			case *channelOpenMsg:
				c.handleChanOpen(msg)
			case *channelOpenConfirmMsg:
				ch := c.chanList.getChan(msg.PeersId)
				if ch == nil {
					return
				}
				ch.msg <- msg
			case *channelOpenFailureMsg:
				ch := c.chanList.getChan(msg.PeersId)
				if ch == nil {
					return
				}
				ch.msg <- msg
			case *channelCloseMsg:
				ch := c.chanList.getChan(msg.PeersId)
				if ch == nil {
					return
				}
				ch.Close()
				close(ch.msg)
				c.chanList.remove(msg.PeersId)
			case *channelEOFMsg:
				ch := c.chanList.getChan(msg.PeersId)
				if ch == nil {
					return
				}
				ch.stdout.eof()
				// RFC 4254 is mute on how EOF affects dataExt messages but
				// it is logical to signal EOF at the same time.
				ch.stderr.eof()
			case *channelRequestSuccessMsg:
				ch := c.chanList.getChan(msg.PeersId)
				if ch == nil {
					return
				}
				ch.msg <- msg
			case *channelRequestFailureMsg:
				ch := c.chanList.getChan(msg.PeersId)
				if ch == nil {
					return
				}
				ch.msg <- msg
			case *channelRequestMsg:
				ch := c.chanList.getChan(msg.PeersId)
				if ch == nil {
					return
				}
				ch.msg <- msg
			case *windowAdjustMsg:
				ch := c.chanList.getChan(msg.PeersId)
				if ch == nil {
					return
				}
				if !ch.remoteWin.add(msg.AdditionalBytes) {
					// invalid window update
					return
				}
			case *globalRequestMsg:
				// This handles keepalive messages and matches
				// the behaviour of OpenSSH.
				if msg.WantReply {
					c.transport.writePacket(marshal(msgRequestFailure, globalRequestFailureMsg{}))
				}
			case *globalRequestSuccessMsg, *globalRequestFailureMsg:
				c.globalRequest.response <- msg
			case *disconnectMsg:
				return
			default:
				fmt.Printf("mainLoop: unhandled message %T: %v\n", msg, msg)
			}
		}
	}
}

// Handle channel open messages from the remote side.
func (c *ClientConn) handleChanOpen(msg *channelOpenMsg) {
	if msg.MaxPacketSize < minPacketLength || msg.MaxPacketSize > 1<<31 {
		c.sendConnectionFailed(msg.PeersId)
	}

	switch msg.ChanType {
	case "forwarded-tcpip":
		laddr, rest, ok := parseTCPAddr(msg.TypeSpecificData)
		if !ok {
			// invalid request
			c.sendConnectionFailed(msg.PeersId)
			return
		}

		l, ok := c.forwardList.lookup(*laddr)
		if !ok {
			// TODO: print on a more structured log.
			fmt.Println("could not find forward list entry for", laddr)
			// Section 7.2, implementations MUST reject spurious incoming
			// connections.
			c.sendConnectionFailed(msg.PeersId)
			return
		}
		raddr, rest, ok := parseTCPAddr(rest)
		if !ok {
			// invalid request
			c.sendConnectionFailed(msg.PeersId)
			return
		}

		ch := newClientChan(c.transport)
		ch.localId = c.chanList.add(ch)
		ch.remoteId = msg.PeersId
		ch.remoteWin.add(msg.PeersWindow)
		ch.maxPacket = msg.MaxPacketSize

		m := channelOpenConfirmMsg{
			PeersId:  ch.remoteId,
			MyId:     ch.localId,
			MyWindow: 1 << 14,

			// As per RFC 4253 6.1, 32k is also the minimum.
			MaxPacketSize: 1 << 15,
		}

		c.transport.writePacket(marshal(msgChannelOpenConfirm, m))
		l <- forward{ch, raddr}
	default:
		// unknown channel type
		m := channelOpenFailureMsg{
			PeersId:  msg.PeersId,
			Reason:   UnknownChannelType,
			Message:  fmt.Sprintf("unknown channel type: %v", msg.ChanType),
			Language: "en_US.UTF-8",
		}
		c.transport.writePacket(marshal(msgChannelOpenFailure, m))
	}
}

// sendGlobalRequest sends a global request message as specified
// in RFC4254 section 4. To correctly synchronise messages, a lock
// is held internally until a response is returned.
func (c *ClientConn) sendGlobalRequest(m interface{}) (*globalRequestSuccessMsg, error) {
	c.globalRequest.Lock()
	defer c.globalRequest.Unlock()
	if err := c.transport.writePacket(marshal(msgGlobalRequest, m)); err != nil {
		return nil, err
	}
	r := <-c.globalRequest.response
	if r, ok := r.(*globalRequestSuccessMsg); ok {
		return r, nil
	}
	return nil, errors.New("request failed")
}

// sendConnectionFailed rejects an incoming channel identified
// by remoteId.
func (c *ClientConn) sendConnectionFailed(remoteId uint32) error {
	m := channelOpenFailureMsg{
		PeersId:  remoteId,
		Reason:   ConnectionFailed,
		Message:  "invalid request",
		Language: "en_US.UTF-8",
	}
	return c.transport.writePacket(marshal(msgChannelOpenFailure, m))
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

// chanList is a thread safe channel list.
type chanList struct {
	// protects concurrent access to chans
	sync.Mutex

	// we determine the local ID of the channel through the index
	// in this slice. When referring to a channel, the remote side
	// sends along our ID, in the PeersId field of the channel
	// message.
	chans []*clientChan

	// This is a debugging aid: it offsets all IDs by this
	// amount. This helps distinguish otherwise identical
	// server/client muxes
	offset uint32
}

// add assigns an ID to the given channel.
func (c *chanList) add(ch *clientChan) uint32 {
	c.Lock()
	defer c.Unlock()
	for i := range c.chans {
		if c.chans[i] == nil {
			c.chans[i] = ch
			return uint32(i) + c.offset
		}
	}
	c.chans = append(c.chans, ch)
	return uint32(len(c.chans)-1) + c.offset
}

// getChan returns the channel for the given ID, or nil if it is
// unknown.
func (c *chanList) getChan(id uint32) *clientChan {
	id -= c.offset

	c.Lock()
	defer c.Unlock()
	if id < uint32(len(c.chans)) {
		return c.chans[id]
	}
	return nil
}

// remove drops the ID for our channel list.
func (c *chanList) remove(id uint32) {
	id -= c.offset
	c.Lock()
	if id < uint32(len(c.chans)) {
		c.chans[id] = nil
	}
	c.Unlock()
}

// dropAll forgets all channels it knows, returning them in a slice.
func (c *chanList) dropAll() []*clientChan {
	var r []*clientChan
	c.Lock()
	defer c.Unlock()
	for _, ch := range c.chans {
		if ch == nil {
			continue
		}
		r = append(r, ch)
	}
	c.chans = nil
	return r
}
