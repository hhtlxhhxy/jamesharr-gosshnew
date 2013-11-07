// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"fmt"
	"io"
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

func min(a uint32, b int) uint32 {
	if a < uint32(b) {
		return a
	}
	return uint32(b)
}
