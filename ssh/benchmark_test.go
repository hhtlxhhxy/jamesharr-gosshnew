// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"errors"
	"io"
	"testing"
)

type dummyPasswd struct{}

func (dummyPasswd) Password(user string) (string, error) {
	return "", nil
}

func sshPipe() (*ClientConn, *ServerConn, error) {
	c1, c2, err := netPipe()
	if err != nil {
		return nil, nil, err
	}

	d := dummyPasswd{}
	clientConf := ClientConfig{
		User: "user",
		Auth: []ClientAuth{
			ClientAuthPassword(&d),
		},
	}
	serverConf := ServerConfig{
		PasswordCallback: func(conn *ServerConn, u, p string) bool { return true },
	}
	serverConf.AddHostKey(ecdsaKey)
	done := make(chan *ServerConn, 1)
	go func() {
		server := Server(c2, &serverConf)
		if err := server.Handshake(); err != nil {
			done <- nil
		}
		done <- server
	}()

	client, err := Client(c1, &clientConf)
	if err != nil {
		return nil, nil, err
	}

	server := <-done
	if server == nil {
		return nil, nil, errors.New("server handshake failed.")
	}
	return client, server, nil
}

func BenchmarkEndToEnd(b *testing.B) {
	b.StopTimer()

	client, server, err := sshPipe()
	if err != nil {
		b.Fatalf("sshPipe: %v", err)
	}

	defer client.Close()
	defer server.Close()

	size := (1 << 20)
	input := make([]byte, size)
	output := make([]byte, size)
	b.SetBytes(int64(size))
	done := make(chan int, 1)

	go func() {
		newCh, err := server.Accept()
		if err != nil {
			b.Fatalf("Client: %v", err)
		}
		ch, incoming, err := newCh.Accept()
		go DiscardIncoming(incoming)
		for i := 0; i < b.N; i++ {
			if _, err := io.ReadFull(ch, output); err != nil {
				b.Fatalf("ReadFull: %v")
			}
		}
		ch.Close()
		done <- 1
	}()

	ch, err := client.mux.OpenChannel("speed", nil)
	if err != nil {
		b.Fatalf("OpenChannel: %v", err)
	}

	b.ResetTimer()
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ch.Write(input); err != nil {
			b.Fatalf("WriteFull: %v")
		}
	}
	ch.Close()
	b.StopTimer()

	<-done
}
