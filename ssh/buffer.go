// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"io"
	"sync"
)

// buffer provides a linked list buffer for data exchange
// between producer and consumer. Theoretically the buffer is
// of unlimited capacity as it does no allocation of its own.
type buffer struct {
	// protects concurrent access to head, tail and closed
	*sync.Cond

	// If set, return ChannelRequests as read errors.
	requestErrors    bool
	incomingRequests []*ChannelRequest

	head *element // the buffer that will be read first
	tail *element // the buffer that will be read last

	closed bool
}

// An element represents a single link in a linked list.
type element struct {
	buf  []byte
	next *element
}

// newBuffer returns an empty buffer that is not closed.
func newBuffer() *buffer {
	e := new(element)
	b := &buffer{
		Cond: newCond(),
		head: e,
		tail: e,
	}
	return b
}

// write makes buf available for Read to receive.
// buf must not be modified after the call to write.
func (b *buffer) write(buf []byte) {
	b.Cond.L.Lock()
	defer b.Cond.L.Unlock()
	e := &element{buf: buf}
	b.tail.next = e
	b.tail = e
	b.Cond.Signal()
}

// addRequest adds a request to be returned from read(). This is a
// temporary hack for compatibility with go.crypto/ssh.
func (b *buffer) addRequest(r *ChannelRequest) {
	b.Cond.L.Lock()
	defer b.Cond.L.Unlock()
	b.incomingRequests = append(b.incomingRequests, r)
	b.Cond.Broadcast()
}

// eof closes the buffer. Reads from the buffer once all
// the data has been consumed will receive os.EOF.
func (b *buffer) eof() error {
	b.Cond.L.Lock()
	defer b.Cond.L.Unlock()
	b.closed = true
	b.Cond.Signal()
	return nil
}

// Read reads data from the internal buffer in buf.  Reads will block
// if no data is available, or until the buffer is closed. If
// requestErrors is set, return pending ChannelRequest as errors.
func (b *buffer) Read(buf []byte) (n int, err error) {
	b.Cond.L.Lock()
	defer b.Cond.L.Unlock()

	for {
		// if there is data in b.head, copy it
		if len(buf) > 0 && len(b.head.buf) > 0 {
			r := copy(buf, b.head.buf)
			buf, b.head.buf = buf[r:], b.head.buf[r:]
			n += r
			continue
		}
		// if there is a next buffer, make it the head
		if len(b.head.buf) == 0 && b.head != b.tail {
			b.head = b.head.next
			continue
		}
		// if at least one byte has been copied, return
		if n > 0 {
			break
		}

		if b.requestErrors && len(b.incomingRequests) > 0 {
			err = *b.incomingRequests[0]
			b.incomingRequests = b.incomingRequests[1:]
			return 0, err
		}

		// if nothing was read, and there is nothing outstanding
		// check to see if the buffer is closed.
		if b.closed {
			err = io.EOF
			break
		}
		if !b.requestErrors && len(buf) == 0 {
			break
		}
		// out of buffers, wait for producer
		b.Cond.Wait()
	}
	return
}
