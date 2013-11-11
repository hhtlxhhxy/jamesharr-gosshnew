// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"io"
	"io/ioutil"
	"sync"
	"testing"
	"time"
)

func muxPair() (*mux, *mux) {
	a, b := memPipe()

	s := newMux(a)
	c := newMux(b)

	go s.Loop()
	go c.Loop()

	return s, c
}

// Returns both ends of a channel, and the mux for the the 2nd
// channel.
func channelPair(t *testing.T) (*channel, *channel, *mux) {
	c, s := muxPair()

	res := make(chan *channel, 1)
	go func() {
		ch, ok := <-s.incomingChannels
		if !ok {
			t.Fatalf("No incoming channel")
		}
		if ch.ChannelType() != "chan" {
			t.Fatalf("got type %q want chan", ch.ChannelType())
		}
		err := ch.Accept()
		if err != nil {
			t.Fatalf("Accept %v", err)
		}
		res <- ch
	}()

	ch, err := c.OpenChannel("chan", nil)
	if err != nil {
		t.Fatalf("OpenChannel: %v", err)
	}

	return <-res, ch, c
}

func TestMuxReadWrite(t *testing.T) {
	s, c, _ := channelPair(t)

	magic := "hello world"
	magicExt := "hello stderr"
	go func() {
		_, err := s.Write([]byte(magic))
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
		_, err = s.Extended(1).Write([]byte(magicExt))
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
		err = s.Close()
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	}()

	var buf [1024]byte
	n, err := c.Read(buf[:])
	if err != nil {
		t.Fatalf("server Read: %v", err)
	}
	got := string(buf[:n])
	if got != magic {
		t.Fatalf("server: got %q want %q", got, magic)
	}

	n, err = c.Extended(1).Read(buf[:])
	if err != nil {
		t.Fatalf("server Read: %v", err)
	}

	got = string(buf[:n])
	if got != magicExt {
		t.Fatalf("server: got %q want %q", got, magic)
	}
}

type timingPacketConn struct {
	packetConn
	idle *time.Timer
}

func (c *timingPacketConn) readPacket() ([]byte, error) {
	p, err := c.packetConn.readPacket()
	if p != nil {
		c.idle.Reset(10 * time.Millisecond)
	}
	return p, err
}

// Returns a channel pair, plus a chan that fires if the read side is idle.
func flowControlChannelPair() (reader *channel, writer *channel, idle <-chan time.Time) {
	wConn, b := memPipe()
	rConn := &timingPacketConn{
		packetConn: b,
		idle:       time.NewTimer(100 * time.Millisecond),
	}
	rMux := newMux(rConn)
	wMux := newMux(wConn)
	go rMux.Loop()
	go wMux.Loop()

	out := make(chan *channel, 1)
	go func() {
		ch, _ := rMux.OpenChannel("flow", nil)
		out <- ch
	}()

	writer = <-wMux.incomingChannels
	writer.Accept()
	reader = <-out
	return reader, writer, rConn.idle.C
}

func TestMuxFlowControl(t *testing.T) {
	reader, writer, idle := flowControlChannelPair()

	// this goroutine reads just a bit.
	readDone := make(chan int, 1)
	go func() {
		b := make([]byte, 1024)
		n, err := reader.Read(b)
		if err != nil || n != len(b) {
			t.Errorf("Read: %v, %d bytes", err, n)
		}
		readDone <- 1
	}()

	// This goroutine writes is blocked from writing by the slow
	// reader
	done := make(chan int, 1)
	go func() {
		largeData := make([]byte, 3*channelWindowSize)
		n, err := writer.Write(largeData)
		if err != io.EOF {
			t.Errorf("want EOF, got %v", err)
		}
		want := 1024 + channelWindowSize
		if n != want {
			t.Errorf("wrote %d, want %d", n, want)
		}
		done <- 1
	}()

	// Wait for a bit for things to subside. The write should be
	// blocked.
	<-idle
	<-readDone

	writer.mux.Disconnect(0, "")
	reader.mux.Disconnect(0, "")

	<-done
}

func TestMuxChannelFlowControl(t *testing.T) {
	reader, writer, idle := flowControlChannelPair()

	closeTrigger := make(chan int, 2)
	// this goroutine reads just a bit.
	go func() {
		b := make([]byte, 1024)
		n, err := reader.Read(b)
		if err != nil || n != len(b) {
			t.Errorf("Read: %v, %d bytes", err, n)
		}
		// Sleep so the writer will block.
		<-closeTrigger
		reader.Close()
		closeTrigger <- 1
	}()

	// This goroutine writes is blocked from writing by the slow
	// reader
	wDone := make(chan int, 1)
	go func() {
		largeData := make([]byte, 3*channelWindowSize)
		n, err := writer.Write(largeData)
		if err != io.EOF {
			t.Errorf("want EOF, got %v", err)
		}
		want := 1024 + channelWindowSize
		if n != want {
			t.Errorf("wrote %d, want %d", n, want)
		}
		wDone <- 1
	}()

	// Wait for a bit for things to subside. The write should be
	// blocked.
	<-idle
	closeTrigger <- 1
	<-wDone
	<-closeTrigger
}

func TestMuxReject(t *testing.T) {
	client, server := muxPair()

	go func() {
		ch, ok := <-server.incomingChannels
		if !ok {
			t.Fatalf("Accept")
		}
		if ch.ChannelType() != "ch" || string(ch.ExtraData()) != "extra" {
			t.Fatalf("unexpected channel: %q, %q", ch.ChannelType(), ch.ExtraData())
		}
		ch.Reject(RejectionReason(42), "message")
	}()

	ch, err := client.OpenChannel("ch", []byte("extra"))
	if ch != nil {
		t.Fatal("openChannel not rejected")
	}

	ocf, ok := err.(*OpenChannelError)
	if !ok {
		t.Errorf("got %#v want *OpenChannelError", err)
	} else if ocf.Reason != 42 || ocf.Message != "message" {
		t.Errorf("got %#v, want {Reason: 42, Message: %q}", ocf, "message")
	}

	want := "ssh: rejected: unknown reason 42 (message)"
	if err.Error() != want {
		t.Errorf("got %q, want %q", err.Error(), want)
	}
}

func TestMuxChannelRequest(t *testing.T) {
	client, server, _ := channelPair(t)
	var received int
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		for r := range server.incomingRequests {
			received++
			if r.WantReply {
				server.AckRequest(r.Request == "yes")
			}
		}
		wg.Done()
	}()
	_, err := client.SendRequest("yes", false, nil)
	if err != nil {
		t.Fatalf("SendRequest: %v", err)
	}
	ok, err := client.SendRequest("yes", true, nil)
	if err != nil {
		t.Fatalf("SendRequest: %v", err)
	}

	if !ok {
		t.Errorf("SendRequest(yes): %v", ok)

	}

	ok, err = client.SendRequest("no", true, nil)
	if err != nil {
		t.Fatalf("SendRequest: %v", err)
	}
	if ok {
		t.Errorf("SendRequest(no): %v", ok)

	}

	client.Close()
	wg.Wait()

	if received != 3 {
		t.Errorf("got %d requests, want %d", received)
	}
}

func TestMuxGlobalRequest(t *testing.T) {
	clientMux, serverMux := muxPair()

	var seen bool
	go func() {
		for r := range serverMux.incomingRequests {
			seen = seen || r.Request == "peek"
			if r.WantReply {
				err := serverMux.AckRequest(r.Request == "yes",
					append([]byte(r.Request), r.Payload...))
				if err != nil {
					t.Errorf("AckRequest: %v", err)
				}
			}
		}
	}()

	_, _, err := clientMux.SendRequest("peek", false, nil)
	if err != nil {
		t.Errorf("SendRequest: %v", err)
	}

	ok, data, err := clientMux.SendRequest("yes", true, []byte("a"))
	if !ok || string(data) != "yesa" || err != nil {
		t.Errorf("SendRequest(\"yes\", true, \"a\"): %v %v %v",
			ok, data, err)
	}
	if ok, data, err := clientMux.SendRequest("yes", true, []byte("a")); !ok || string(data) != "yesa" || err != nil {
		t.Errorf("SendRequest(\"yes\", true, \"a\"): %v %v %v",
			ok, data, err)
	}

	if ok, data, err := clientMux.SendRequest("no", true, []byte("a")); ok || string(data) != "noa" || err != nil {
		t.Errorf("SendRequest(\"no\", true, \"a\"): %v %v %v",
			ok, data, err)
	}

	clientMux.Disconnect(0, "")
	if !seen {
		t.Errorf("never saw 'peek' request")
	}
}

func TestMuxGlobalRequestUnblock(t *testing.T) {
	clientMux, serverMux := muxPair()

	result := make(chan error, 1)
	go func() {
		_, _, err := clientMux.SendRequest("hello", true, nil)
		result <- err
	}()

	<-serverMux.incomingRequests
	serverMux.conn.Close()
	err := <-result

	if err != io.EOF {
		t.Errorf("want EOF, got %v", io.EOF)
	}
}

func TestMuxChannelRequestUnblock(t *testing.T) {
	a, b, connB := channelPair(t)

	result := make(chan error, 1)
	go func() {
		_, err := a.SendRequest("hello", true, nil)
		result <- err
	}()

	<-b.incomingRequests
	connB.conn.Close()
	err := <-result

	if err != io.EOF {
		t.Errorf("want EOF, got %v", err)
	}
}

func TestMuxDisconnect(t *testing.T) {
	a, b := muxPair()
	go func() {
		for r := range b.incomingRequests {
			if r.WantReply {
				b.AckRequest(true, nil)
			}
		}
	}()

	a.Disconnect(42, "whatever")
	ok, _, err := a.SendRequest("hello", true, nil)
	if ok || err == nil {
		t.Errorf("got reply after disconnecting")
	}
}

func TestMuxCloseChannel(t *testing.T) {
	r, w, _ := channelPair(t)

	timeout := time.After(10 * time.Millisecond)
	result := make(chan error, 1)
	go func() {
		var b [1024]byte
		_, err := r.Read(b[:])
		result <- err
	}()
	if err := w.Close(); err != nil {
		t.Errorf("w.Close: %v", err)
	}

	if _, err := w.Write([]byte("hello")); err != io.EOF {
		t.Errorf("got err %v, want io.EOF after Close", err)
	}

	select {
	case e := <-result:
		if e != io.EOF {
			t.Errorf("got %v (%T), want io.EOF", e, e)
		}
	case <-timeout:
		t.Errorf("timed out waiting for read to exit")
	}
}

func TestMuxCloseWriteChannel(t *testing.T) {
	r, w, _ := channelPair(t)

	timeout := time.After(10 * time.Millisecond)
	result := make(chan error, 1)
	go func() {
		var b [1024]byte
		_, err := r.Read(b[:])
		result <- err
	}()
	if err := w.CloseWrite(); err != nil {
		t.Errorf("w.CloseWrite: %v", err)
	}

	if _, err := w.Write([]byte("hello")); err != io.EOF {
		t.Errorf("got err %v, want io.EOF after CloseWrite", err)
	}

	select {
	case e := <-result:
		if e != io.EOF {
			t.Errorf("got %v (%T), want io.EOF", e, e)
		}
	case <-timeout:
		t.Errorf("timed out waiting for read to exit")
	}
}

func TestMuxInvalidRecord(t *testing.T) {
	a, b := muxPair()

	packet := make([]byte, 1+4+4+1)
	packet[0] = msgChannelData
	marshalUint32(packet[1:], 29348723 /* invalid channel id */)
	marshalUint32(packet[5:], 1)
	packet[9] = 42

	a.conn.writePacket(packet)
	go a.SendRequest("hello", false, nil)
	// 'a' wrote an invalid packet, so 'b' has exited.
	req, ok := <-b.incomingRequests
	if ok {
		t.Errorf("got request %#v after receiving invalid packet", req)
	}
}

func TestZeroWindowAdjust(t *testing.T) {
	a, b, _ := channelPair(t)

	go func() {
		io.WriteString(a, "hello")
		// bogus adjust.
		a.sendMessage(
			msgChannelWindowAdjust, windowAdjustMsg{})
		io.WriteString(a, "world")
		a.Close()
	}()

	want := "helloworld"
	c, _ := ioutil.ReadAll(b)
	if string(c) != want {
		t.Errorf("got %q want %q", c, want)
	}
}

func TestMuxMaxPacketSize(t *testing.T) {
	a, b, _ := channelPair(t)

	large := make([]byte, a.maxPacket+1)
	if err := a.writePacket(large); err == nil {
		t.Errorf("channel sent out packet larger than maxPacket")
	}

	packet := make([]byte, 1+4+4+1+len(large))
	packet[0] = msgChannelData
	marshalUint32(packet[1:], a.remoteId)
	marshalUint32(packet[5:], uint32(len(large)))
	packet[9] = 42

	if err := a.mux.conn.writePacket(packet); err != nil {
		t.Errorf("could not send packet")
	}

	go a.SendRequest("hello", false, nil)

	_, ok := <-b.incomingRequests
	if ok {
		t.Errorf("connection still alive after receiving large packet.")
	}
}

// Don't ship code with debug=true.
func TestDebug(t *testing.T) {
	if debug {
		t.Error("debug switched on")
	}
}
