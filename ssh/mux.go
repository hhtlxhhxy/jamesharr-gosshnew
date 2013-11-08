// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"sync/atomic"
)

// If set, debug will log print messages sent and received.
const debug = false

// chanList is a thread safe channel list.
type chanList struct {
	// protects concurrent access to chans
	sync.Mutex

	// chans are indexed by the local id of the channel, which the
	// other side should send in the PeersId field.
	chans []*channel

	// This is a debugging aid: it offsets all IDs by this
	// amount. This helps distinguish otherwise identical
	// server/client muxes
	offset uint32
}

// Assigns a channel ID to the given channel.
func (c *chanList) add(ch *channel) uint32 {
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

// getChan returns the channel for the given ID.
func (c *chanList) getChan(id uint32) *channel {
	id -= c.offset

	c.Lock()
	defer c.Unlock()
	if id < uint32(len(c.chans)) {
		return c.chans[id]
	}
	return nil
}

func (c *chanList) remove(id uint32) {
	id -= c.offset
	c.Lock()
	if id < uint32(len(c.chans)) {
		c.chans[id] = nil
	}
	c.Unlock()
}

// dropAll forgets all channels it knows, returning them in a slice.
func (c *chanList) dropAll() []*channel {
	c.Lock()
	defer c.Unlock()
	var r []*channel

	for _, ch := range c.chans {
		if ch == nil {
			continue
		}
		r = append(r, ch)
	}
	c.chans = nil
	return r
}

// mux represents the state for the SSH connection protocol, which
// multiplexes many channels onto a single packet transport.
type mux struct {
	conn     packetConn
	chanList chanList

	incomingChannels chan *channel

	globalSentMu     sync.Mutex
	globalResponses  chan interface{}
	incomingRequests chan *ChannelRequest
}

// Each new chanList instantiation has a different offset.
var globalOff uint32

// newMux returns a mux that runs over the given connection. Caller
// should run Loop for returned mux.
func newMux(p packetConn) *mux {
	m := &mux{
		conn:             p,
		incomingChannels: make(chan *channel, 16),
		globalResponses:  make(chan interface{}, 1),
		incomingRequests: make(chan *ChannelRequest, 16),
	}
	m.chanList.offset = atomic.AddUint32(&globalOff, 1)
	return m
}

func (m *mux) sendMessage(code byte, msg interface{}) error {
	p := marshal(code, msg)
	return m.conn.writePacket(p)
}

// SendRequest sends a global request. If wantReply is set, the return
// includes success status and extra data. See also RFC4254, section 4.
func (m *mux) SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	if wantReply {
		m.globalSentMu.Lock()
		defer m.globalSentMu.Unlock()
	}

	if err := m.sendMessage(msgGlobalRequest,
		globalRequestMsg{
			Type:      name,
			WantReply: wantReply,
			Data:      payload,
		}); err != nil {
		return false, nil, err
	}

	if wantReply {
		msg, ok := <-m.globalResponses
		if !ok {
			return false, nil, io.EOF
		}
		switch msg := msg.(type) {
		case *globalRequestFailureMsg:
			return false, msg.Data, nil
		case *globalRequestSuccessMsg:
			return true, msg.Data, nil
		default:
			return false, nil, fmt.Errorf("ssh: unexpected response %#v", msg)
		}
	}

	return false, nil, nil
}

// AckRequest must be called after processing a global request that
// has WantReply set.
func (m *mux) AckRequest(ok bool, data []byte) error {
	if ok {
		return m.sendMessage(msgRequestSuccess,
			globalRequestSuccessMsg{Data: data})
	}
	return m.sendMessage(msgRequestFailure, globalRequestFailureMsg{Data: data})
}

// TODO(hanwen): Disconnect is a transport layer message. We should
// probably send and receive Disconnect somewhere in the transport
// code.

// Disconnect sends a disconnect message.
func (m *mux) Disconnect(reason uint32, message string) error {
	return m.sendMessage(msgDisconnect, disconnectMsg{
		Reason:  reason,
		Message: message,
	})
}

// Loop runs the connection machine. It will process packets until an
// error is encountered, returning that error. When the loop exits,
// the connection is closed.
func (m *mux) Loop() error {
	var err error
	for err == nil {
		err = m.onePacket()
	}
	if debug && err != nil {
		log.Println("loop exit", err)
	}

	for _, ch := range m.chanList.dropAll() {
		ch.mu.Lock()
		ch.sentClose = true
		ch.mu.Unlock()
		ch.pending.eof()
		ch.extPending.eof()
		close(ch.incomingRequests)
		// ch.msg is otherwise only called from onePacket, so
		// this is safe.
		close(ch.msg)
	}

	close(m.incomingChannels)
	close(m.incomingRequests)
	close(m.globalResponses)

	m.conn.Close()
	return err
}

// onePacket reads and processes one packet.
func (m *mux) onePacket() error {
	packet, err := m.conn.readPacket()
	if err != nil {
		return err
	}

	if debug {
		p, _ := decode(packet)
		log.Printf("decoding(%d): %d %#v - %d bytes", m.chanList.offset, packet[0], p, len(packet))
	}

	switch packet[0] {
	case msgNewKeys:
		// Ignore notification of key change.
		return nil
	case msgDisconnect:
		return m.handleDisconnect(packet)
	case msgChannelOpen:
		return m.handleChannelOpen(packet)
	case msgGlobalRequest, msgRequestSuccess, msgRequestFailure:
		return m.handleGlobalPacket(packet)
	}

	// assume a channel packet.
	if len(packet) < 5 {
		return ParseError{packet[0]}
	}
	id := binary.BigEndian.Uint32(packet[1:])
	ch := m.chanList.getChan(id)
	if ch == nil {
		return fmt.Errorf("ssh: invalid channel %d", id)
	}

	return ch.handlePacket(packet)
}

func (m *mux) handleDisconnect(packet []byte) error {
	var d disconnectMsg
	if err := unmarshal(&d, packet, msgDisconnect); err != nil {
		return err
	}

	if debug {
		// TODO(hanwen): the disconnect message has more
		// diagnostics. We could try to return those?
		log.Printf("caught disconnect: %v", d)
	}
	return io.EOF
}

func (m *mux) handleGlobalPacket(packet []byte) error {
	msg, err := decode(packet)
	if err != nil {
		return err
	}

	switch msg := msg.(type) {
	case *globalRequestMsg:
		m.incomingRequests <- &ChannelRequest{
			msg.Type,
			msg.WantReply,
			msg.Data,
		}
	case *globalRequestSuccessMsg, *globalRequestFailureMsg:
		m.globalResponses <- msg
	default:
		panic(fmt.Sprintf("not a global message %#v", msg))
	}

	return nil
}

// handleChannelOpen schedules a channel to be Accept()ed.
func (m *mux) handleChannelOpen(packet []byte) error {
	var msg channelOpenMsg
	if err := unmarshal(&msg, packet, msgChannelOpen); err != nil {
		return err
	}

	if msg.MaxPacketSize < minPacketLength || msg.MaxPacketSize > 1<<31 {
		failMsg := channelOpenFailureMsg{
			PeersId:  msg.PeersId,
			Reason:   ConnectionFailed,
			Message:  "invalid request",
			Language: "en_US.UTF-8",
		}
		return m.sendMessage(msgChannelOpenFailure, failMsg)
	}

	c := m.newChannel(msg.ChanType, msg.TypeSpecificData)
	c.remoteId = msg.PeersId
	c.maxPacket = msg.MaxPacketSize
	c.remoteWin.add(msg.PeersWindow)
	m.incomingChannels <- c
	return nil
}

// OpenChannelError is returned the other side rejects our OpenChannel
// request.
type OpenChannelError struct {
	Reason  RejectionReason
	Message string
}

func (e *OpenChannelError) Error() string {
	return fmt.Sprintf("ssh: rejected: %s (%s)", e.Reason, e.Message)
}

// OpenChannel asks for a new channel. If the other side rejects, it
// returns a *OpenChannelError.
func (m *mux) OpenChannel(chanType string, extra []byte) (*channel, error) {
	ch := m.newChannel(chanType, extra)

	// As per RFC 4253, section 6.1, 32k is also the minimum.
	ch.maxPacket = 1 << 15

	open := channelOpenMsg{
		ChanType:         chanType,
		PeersWindow:      ch.myWindow,
		MaxPacketSize:    ch.maxPacket,
		TypeSpecificData: extra,
		PeersId:          ch.localId,
	}
	if err := m.sendMessage(msgChannelOpen, open); err != nil {
		return nil, err
	}

	switch msg := (<-ch.msg).(type) {
	case *channelOpenConfirmMsg:
		if msg.MaxPacketSize < minPacketLength || msg.MaxPacketSize > 1<<31 {
			return nil, errors.New("ssh: invalid MaxPacketSize from peer")
		}
		// fixup remoteId field
		ch.remoteId = msg.MyId
		ch.maxPacket = msg.MaxPacketSize
		ch.remoteWin.add(msg.MyWindow)
		ch.decided = true
		return ch, nil
	case *channelOpenFailureMsg:
		m.chanList.remove(open.PeersId)
		return nil, &OpenChannelError{msg.Reason, msg.Message}
	default:
		return nil, fmt.Errorf("ssh: unexpected packet %T", msg)
	}
}