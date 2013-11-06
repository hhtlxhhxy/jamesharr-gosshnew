// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"errors"
	"fmt"
	"io"
	"sync/atomic"
)

const minPacketLength = 9

// A Channel is an ordered, reliable, duplex stream that is
// multiplexed over an SSH connection.
type Channel interface {
	// Accept accepts the channel creation request.
	Accept() error

	// Reject rejects the channel creation request. After calling
	// this, no other methods on the Channel may be called.
	Reject(reason RejectionReason, message string) error

	// Read may return a ChannelRequest as an error.
	Read(data []byte) (int, error)
	Write(data []byte) (int, error)

	// Signals end of channel use. No data may be sent after this
	// call.
	Close() error

	// Stderr returns an io.Writer that writes to this channel with the
	// extended data type set to stderr.
	Stderr() io.Writer

	// AckRequest either sends an ack or nack to the channel
	// request. It should only be called if the last
	// ChannelRequest had a WantReply
	AckRequest(ok bool) error

	// ChannelType returns the type of the channel, as supplied by the
	// client.
	ChannelType() string

	// ExtraData returns the arbitrary payload for this channel, as supplied
	// by the client. This data is specific to the channel type.
	ExtraData() []byte
}

// ChannelRequest is a request sent outside of the normal stream of
// bytes.
type ChannelRequest struct {
	Request   string
	WantReply bool
	Payload   []byte
}

func (c ChannelRequest) Error() string {
	return "ssh: channel request received"
}

// RejectionReason is an enumeration used when rejecting channel creation
// requests. See RFC 4254, section 5.1.
type RejectionReason uint32

const (
	Prohibited RejectionReason = iota + 1
	ConnectionFailed
	UnknownChannelType
	ResourceShortage
)

// String converts the rejection reason to human readable form.
func (r RejectionReason) String() string {
	switch r {
	case Prohibited:
		return "administratively prohibited"
	case ConnectionFailed:
		return "connect failed"
	case UnknownChannelType:
		return "unknown channel type"
	case ResourceShortage:
		return "resource shortage"
	}
	return fmt.Sprintf("unknown reason %d", int(r))
}

type channel struct {
	packetConn        // the underlying transport
	localId, remoteId uint32
	remoteWin         window
	maxPacket         uint32
	isClosed          uint32 // atomic bool, non zero if true
}

func (c *channel) sendWindowAdj(n int) error {
	msg := windowAdjustMsg{
		PeersId:         c.remoteId,
		AdditionalBytes: uint32(n),
	}
	return c.writePacket(marshal(msgChannelWindowAdjust, msg))
}

// sendEOF sends EOF to the remote side. RFC 4254 Section 5.3
func (c *channel) sendEOF() error {
	return c.writePacket(marshal(msgChannelEOF, channelEOFMsg{
		PeersId: c.remoteId,
	}))
}

// sendClose informs the remote side of our intent to close the channel.
func (c *channel) sendClose() error {
	return c.packetConn.writePacket(marshal(msgChannelClose, channelCloseMsg{
		PeersId: c.remoteId,
	}))
}

func (c *channel) sendChannelOpenFailure(reason RejectionReason, message string) error {
	reject := channelOpenFailureMsg{
		PeersId:  c.remoteId,
		Reason:   reason,
		Message:  message,
		Language: "en",
	}
	return c.writePacket(marshal(msgChannelOpenFailure, reject))
}

func (c *channel) writePacket(b []byte) error {
	if c.closed() {
		return io.EOF
	}
	if uint32(len(b)) > c.maxPacket {
		return fmt.Errorf("ssh: cannot write %d bytes, maxPacket is %d bytes", len(b), c.maxPacket)
	}
	return c.packetConn.writePacket(b)
}

func (c *channel) closed() bool {
	return atomic.LoadUint32(&c.isClosed) > 0
}

func (c *channel) setClosed() bool {
	return atomic.CompareAndSwapUint32(&c.isClosed, 0, 1)
}

// A clientChan represents a single RFC 4254 channel multiplexed
// over a SSH connection.
type clientChan struct {
	channel
	stdin  *chanWriter
	stdout *chanReader
	stderr *chanReader
	msg    chan interface{}
}

// newClientChan returns a partially constructed *clientChan
// using the local id provided. To be usable clientChan.remoteId
// needs to be assigned once known.
func newClientChan(cc packetConn) *clientChan {
	c := &clientChan{
		channel: channel{
			packetConn: cc,
			remoteWin:  window{Cond: newCond()},
		},
		msg: make(chan interface{}, 16),
	}
	c.stdin = &chanWriter{
		channel: &c.channel,
	}
	c.stdout = &chanReader{
		channel: &c.channel,
		buffer:  newBuffer(),
	}
	c.stderr = &chanReader{
		channel: &c.channel,
		buffer:  newBuffer(),
	}
	return c
}

// waitForChannelOpenResponse, if successful, fills out
// the remoteId and records any initial window advertisement.
func (c *clientChan) waitForChannelOpenResponse() error {
	switch msg := (<-c.msg).(type) {
	case *channelOpenConfirmMsg:
		if msg.MaxPacketSize < minPacketLength || msg.MaxPacketSize > 1<<31 {
			return errors.New("ssh: invalid MaxPacketSize from peer")
		}
		// fixup remoteId field
		c.remoteId = msg.MyId
		c.maxPacket = msg.MaxPacketSize
		c.remoteWin.add(msg.MyWindow)
		return nil
	case *channelOpenFailureMsg:
		return errors.New(safeString(msg.Message))
	}
	return errors.New("ssh: unexpected packet")
}

// Close signals the intent to close the channel.
func (c *clientChan) Close() error {
	if !c.setClosed() {
		return errors.New("ssh: channel already closed")
	}
	c.stdout.eof()
	c.stderr.eof()
	return c.sendClose()
}

// A chanWriter represents the stdin of a remote process.
type chanWriter struct {
	*channel
	// indicates the writer has been closed. eof is owned by the
	// caller of Write/Close.
	eof bool
}

// Write writes data to the remote process's standard input.
func (w *chanWriter) Write(data []byte) (written int, err error) {
	const headerLength = 9 // 1 byte message type, 4 bytes remoteId, 4 bytes data length
	for len(data) > 0 {
		if w.eof || w.closed() {
			err = io.EOF
			return
		}
		// never send more data than maxPacket even if
		// there is sufficient window.
		n := min(w.maxPacket-headerLength, len(data))
		r := w.remoteWin.reserve(n)
		n = r
		remoteId := w.remoteId
		packet := []byte{
			msgChannelData,
			byte(remoteId >> 24), byte(remoteId >> 16), byte(remoteId >> 8), byte(remoteId),
			byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n),
		}
		if err = w.writePacket(append(packet, data[:n]...)); err != nil {
			break
		}
		data = data[n:]
		written += int(n)
	}
	return
}

func min(a uint32, b int) uint32 {
	if a < uint32(b) {
		return a
	}
	return uint32(b)
}

func (w *chanWriter) Close() error {
	w.eof = true
	return w.sendEOF()
}

// A chanReader represents stdout or stderr of a remote process.
type chanReader struct {
	*channel // the channel backing this reader
	*buffer
}

// Read reads data from the remote process's stdout or stderr.
func (r *chanReader) Read(buf []byte) (int, error) {
	n, err := r.buffer.Read(buf)
	if err != nil {
		if err == io.EOF {
			return n, err
		}
		return 0, err
	}
	err = r.sendWindowAdj(n)
	if err == io.EOF && n > 0 {
		// sendWindowAdjust can return io.EOF if the remote peer has
		// closed the connection, however we want to defer forwarding io.EOF to the
		// caller of Read until the buffer has been drained.
		err = nil
	}
	return n, err
}
