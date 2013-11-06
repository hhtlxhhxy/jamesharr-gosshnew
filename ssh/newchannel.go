// Copyright 2011 The Go Authors. All rights reserved.
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
)

// channel is a new implementation of the Channel interface that works
// with the mux class. We'll rename it when we make the existing code
// use it.
type nChannel struct {
	// R/O after creation
	chanType          string
	extraData         []byte
	localId, remoteId uint32
	maxPacket         uint32
	mux               *mux

	// If set, we have called Accept or Reject on this channel
	decided bool

	// Pending internal channel messages.
	msg chan interface{}

	// Pending user-serviceable messages.
	sentRequestMu sync.Mutex

	incomingRequests chan *ChannelRequest

	sentEOF bool

	// thread-safe data
	remoteWin  window
	pending    *buffer
	extPending *buffer

	// Protects all of the below.
	mu        sync.Mutex
	myWindow  uint32
	sentClose bool
}

func (c *nChannel) getWindowSpace(max uint32) (uint32, error) {
	// check if closed?
	return c.remoteWin.reserve(max), nil
}

// writePacket sends the packet over the wire. If the packet is a
// channel close, it updates sentClose. This method takes the lock
// c.mu.
func (c *nChannel) writePacket(packet []byte) error {
	if uint32(len(packet)) > c.maxPacket {
		return fmt.Errorf("ssh: cannot write %d bytes, maxPacket is %d bytes", len(packet), c.maxPacket)
	}

	c.mu.Lock()
	if c.sentClose {
		c.mu.Unlock()
		return io.EOF
	}
	c.sentClose = (packet[0] == msgChannelClose)
	err := c.mux.conn.writePacket(packet)
	c.mu.Unlock()
	return err
}

func (c *nChannel) sendMessage(code byte, msg interface{}) error {
	if debug {
		log.Printf("send %d: %#v", c.mux.nChanList.offset, msg)
	}

	p := marshal(code, msg)
	binary.BigEndian.PutUint32(p[1:], c.remoteId)
	return c.writePacket(p)
}

func (c *nChannel) WriteExtended(data []byte, extendedCode uint32) (n int, err error) {
	if c.sentEOF {
		return 0, io.EOF
	}
	// 1 byte message type, 4 bytes remoteId, 4 bytes data length
	opCode := byte(msgChannelData)
	headerLength := uint32(9)
	if extendedCode > 0 {
		headerLength += 4
		opCode = msgChannelExtendedData
	}

	for len(data) > 0 {
		space := min(c.maxPacket-headerLength, len(data))
		if space, err = c.getWindowSpace(space); err != nil {
			return n, err
		}
		todo := data
		if uint32(len(todo)) > space {
			todo = todo[:space]
		}

		packet := make([]byte, headerLength+uint32(len(todo)))
		packet[0] = opCode
		marshalUint32(packet[1:], c.remoteId)
		if extendedCode > 0 {
			marshalUint32(packet[5:], uint32(extendedCode))
		}
		marshalUint32(packet[headerLength-4:], uint32(len(todo)))
		copy(packet[headerLength:], todo)
		if err = c.writePacket(packet); err != nil {
			return n, err
		}

		n += len(todo)
		data = data[len(todo):]
	}

	return n, err
}

func (c *nChannel) handleData(packet []byte) error {
	sz := 9
	if packet[0] == msgChannelExtendedData {
		sz = 13
	}
	if len(packet) < sz {
		// malformed data packet
		return ParseError{packet[0]}
	}

	var extended uint32
	if sz > 9 {
		extended = binary.BigEndian.Uint32(packet[5:])
	}

	length := binary.BigEndian.Uint32(packet[sz-4 : sz])
	if length == 0 {
		return nil
	}
	data := packet[sz:]
	if length != uint32(len(data)) {
		return errors.New("ssh: wrong packet length")
	}

	c.mu.Lock()
	if c.myWindow < length {
		c.mu.Unlock()
		// TODO(hanwen): should send Disconnect with reason?
		return errors.New("ssh: remote side wrote too much")
	}
	c.myWindow -= length
	c.mu.Unlock()

	if extended == 1 {
		c.extPending.write(data)
	} else if extended > 0 {
		// discard other extended data.
	} else {
		c.pending.write(data)
	}
	return nil
}

func (c *nChannel) adjustWindow(n uint32) error {
	c.mu.Lock()
	c.myWindow += uint32(n)
	c.mu.Unlock()
	return c.sendMessage(msgChannelWindowAdjust, windowAdjustMsg{
		AdditionalBytes: uint32(n),
	})
}

func (c *nChannel) ReadExtended(data []byte, extended uint32) (n int, err error) {
	if extended == 1 {
		n, err = c.extPending.Read(data)
	} else if extended == 0 {
		n, err = c.pending.Read(data)
	} else {
		return 0, fmt.Errorf("ssh: extended code %d unimplemented", extended)
	}

	if n > 0 {
		err = c.adjustWindow(uint32(n))
		// sendWindowAdjust can return io.EOF if the remote
		// peer has closed the connection, however we want to
		// defer forwarding io.EOF to the caller of Read until
		// the buffer has been drained.
		if n > 0 && err == io.EOF {
			err = nil
		}
	}

	return n, err
}

func (c *nChannel) handlePacket(packet []byte) error {
	if uint32(len(packet)) > c.maxPacket {
		// TODO(hanwen): should send Disconnect?
		return errors.New("ssh: incoming packet exceeds maximum size")
	}

	switch packet[0] {
	case msgChannelData, msgChannelExtendedData:
		return c.handleData(packet)
	case msgChannelClose:
		// Ack the close.
		c.sendMessage(msgChannelClose, channelCloseMsg{
			PeersId: c.remoteId})

		c.pending.eof()
		c.extPending.eof()
		close(c.msg)
		close(c.incomingRequests)
		c.mux.nChanList.remove(c.localId)

		return nil
	case msgChannelEOF:
		// RFC 4254 is mute on how EOF affects dataExt messages but
		// it is logical to signal EOF at the same time.
		c.extPending.eof()

		// For ServerConn, ChannelRequests are actually output
		// as Read error. This means that no requests can be
		// processed after EOF is sent, which is a bug
		c.pending.eof()
		return nil
	}

	decoded, err := decode(packet)
	if err != nil {
		return err
	}

	switch msg := decoded.(type) {
	case *windowAdjustMsg:
		if !c.remoteWin.add(msg.AdditionalBytes) {
			return fmt.Errorf("invalid window update %d", msg.AdditionalBytes)
		}

	case *channelRequestMsg:
		req := ChannelRequest{
			Request:   msg.Request,
			WantReply: msg.WantReply,
			Payload:   msg.RequestSpecificData,
		}

		c.incomingRequests <- &req
	default:
		c.msg <- msg
	}
	return nil
}

func (m *mux) newChannel(chanType string, extraData []byte) *nChannel {
	ch := &nChannel{
		remoteWin:        window{Cond: newCond()},
		myWindow:         defaultWindowSize,
		pending:          newBuffer(),
		extPending:       newBuffer(),
		incomingRequests: make(chan *ChannelRequest, 16),
		msg:              make(chan interface{}, 16),
		chanType:         chanType,
		extraData:        extraData,
		mux:              m,
	}

	ch.localId = m.nChanList.add(ch)
	ch.myWindow = defaultWindowSize

	return ch
}

var errUndecided = errors.New("ssh: must Accept or Reject channel")
var errDecidedAlready = errors.New("ssh: can call Accept or Reject only once")

type extChannel struct {
	code uint32
	ch   *nChannel
}

func (e *extChannel) Write(data []byte) (n int, err error) {
	return e.ch.WriteExtended(data, e.code)
}

func (e *extChannel) Read(data []byte) (n int, err error) {
	return e.ch.ReadExtended(data, e.code)
}

func (c *nChannel) Accept() error {
	if c.decided {
		return errDecidedAlready
	}
	confirm := channelOpenConfirmMsg{
		PeersId:       c.remoteId,
		MyId:          c.localId,
		MyWindow:      c.myWindow,
		MaxPacketSize: c.maxPacket,
	}
	c.decided = true
	if err := c.sendMessage(msgChannelOpenConfirm, confirm); err != nil {
		return err
	}

	return nil
}

func (ch *nChannel) Reject(reason RejectionReason, message string) error {
	if ch.decided {
		return errDecidedAlready
	}
	reject := channelOpenFailureMsg{
		PeersId:  ch.remoteId,
		Reason:   reason,
		Message:  message,
		Language: "en",
	}
	ch.decided = true
	return ch.sendMessage(msgChannelOpenFailure, reject)
}

func (ch *nChannel) Read(data []byte) (int, error) {
	if !ch.decided {
		return 0, errUndecided
	}
	return ch.ReadExtended(data, 0)
}

func (ch *nChannel) Write(data []byte) (int, error) {
	if !ch.decided {
		return 0, errUndecided
	}
	return ch.WriteExtended(data, 0)
}

func (ch *nChannel) CloseWrite() error {
	if !ch.decided {
		return errUndecided
	}
	ch.sentEOF = true
	return ch.sendMessage(msgChannelEOF, channelEOFMsg{
		PeersId: ch.remoteId})
}

func (ch *nChannel) Close() error {
	if !ch.decided {
		return errUndecided
	}

	return ch.sendMessage(msgChannelClose, channelCloseMsg{
		PeersId: ch.remoteId})
}

func (ch *nChannel) Extended(code uint32) io.ReadWriter {
	if !ch.decided {
		return nil
	}
	return &extChannel{code, ch}
}

// SendRequest sends a channel request. If wantReply is set, it will
// wait for a reply and return the result as a boolean.
func (ch *nChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	if !ch.decided {
		return false, errUndecided
	}

	if wantReply {
		ch.sentRequestMu.Lock()
		defer ch.sentRequestMu.Unlock()
	}

	msg := channelRequestMsg{
		PeersId:             ch.remoteId,
		Request:             name,
		WantReply:           wantReply,
		RequestSpecificData: payload,
	}

	if err := ch.sendMessage(msgChannelRequest, msg); err != nil {
		return false, err
	}

	if wantReply {
		m, ok := (<-ch.msg)
		if !ok {
			return false, io.EOF
		}
		switch m.(type) {
		case *channelRequestFailureMsg:
			return false, nil
		case *channelRequestSuccessMsg:
			return true, nil
		default:
			return false, fmt.Errorf("unexpected response %#v", m)
		}
	}

	return false, nil
}

// AckRequest either sends an ack or nack to the channel request.
func (ch *nChannel) AckRequest(ok bool) error {
	if !ch.decided {
		return errUndecided
	}

	var msg interface{}
	var code byte
	if !ok {
		code = msgChannelFailure
		msg = channelRequestFailureMsg{
			PeersId: ch.remoteId,
		}
	} else {
		code = msgChannelSuccess
		msg = channelRequestSuccessMsg{
			PeersId: ch.remoteId,
		}
	}
	return ch.sendMessage(code, msg)
}

func (ch *nChannel) ChannelType() string {
	return ch.chanType
}

func (ch *nChannel) ExtraData() []byte {
	return ch.extraData
}

// compatChannel is a hack to implement legacy go.crypto/ssh Channel's
// handing of channel requests.
type compatChannel struct {
	*nChannel
}

func newCompatChannel(ch *nChannel) *compatChannel {
	c := &compatChannel{ch}
	go c.loop()
	return c
}

func (c *compatChannel) loop() {
	for r := range c.nChannel.incomingRequests {
		c.nChannel.pending.addRequest(r)
	}
}

func (c *compatChannel) Stderr() io.Writer {
	return c.Extended(1)
}

func (c *compatChannel) Read(buf []byte) (int, error) {
	return c.nChannel.pending.read(buf, true)
}
