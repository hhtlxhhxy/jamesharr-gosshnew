// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"strconv"
	"testing"
)

func startAgent(t *testing.T) (address string, cleanup func()) {
	bin, err := exec.LookPath("ssh-agent")
	if err != nil {
		t.Skip("could not find ssh-agent")
	}

	cmd := exec.Command(bin, "-s")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("cmd.Output: %v", err)
	}

	/* Output looks like:

		   SSH_AUTH_SOCK=/tmp/ssh-P65gpcqArqvH/agent.15541; export SSH_AUTH_SOCK;
	           SSH_AGENT_PID=15542; export SSH_AGENT_PID;
	           echo Agent pid 15542;
	*/
	fields := bytes.Split(out, []byte(";"))
	line := bytes.SplitN(fields[0], []byte("="), 2)
	socket := line[1]

	line = bytes.SplitN(fields[2], []byte("="), 2)
	pidStr := line[1]
	pid, err := strconv.Atoi(string(pidStr))
	if err != nil {
		t.Fatalf("Atoi(%q): %v", pidStr, err)
	}
	return string(socket), func() {
		proc, _ := os.FindProcess(pid)
		if proc != nil {
			proc.Kill()
		}
	}
}

func TestAgent(t *testing.T) {
	socket, cleanup := startAgent(t)
	defer cleanup()
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	defer conn.Close()

	ac := NewAgentClient(conn)
	keys, err := ac.RequestIdentities()
	if err != nil {
		t.Fatalf("RequestIdentities: %v", err)
	}
	if len(keys) > 0 {
		t.Errorf("got %d keys, want 0", len(keys))
	}
	if err := ac.insert(rsaKey, "comment"); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if keys, _ := ac.RequestIdentities(); len(keys) != 1 || keys[0].Comment != "comment" {
		t.Fatalf("got %v, want 1 key with comment `comment`", keys)
	}
	data := []byte("hello")
	sigBytes, err := ac.SignRequest(rsaKey.PublicKey(), data)
	if err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	sig, _, ok := parseSignatureBody(sigBytes)
	if !ok {
		t.Fatalf("parseSignatureBody(%q) failed", sig)
	}
	if !rsaKey.PublicKey().Verify(data, sig.Blob) {
		t.Fatalf("key signature does not validate")
	}
}
