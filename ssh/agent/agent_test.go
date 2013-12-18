// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package agent

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"os/exec"
	"strconv"
	"testing"

	"code.google.com/p/gosshnew/ssh"
)

const rsaKeySerialized = `-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBALdGZxkXDAjsYk10ihwU6Id2KeILz1TAJuoq4tOgDWxEEGeTrcld
r/ZwVaFzjWzxaf6zQIJbfaSEAhqD5yo72+sCAwEAAQJBAK8PEVU23Wj8mV0QjwcJ
tZ4GcTUYQL7cF4+ezTCE9a1NrGnCP2RuQkHEKxuTVrxXt+6OF15/1/fuXnxKjmJC
nxkCIQDaXvPPBi0c7vAxGwNY9726x01/dNbHCE0CBtcotobxpwIhANbbQbh3JHVW
2haQh4fAG5mhesZKAGcxTyv4mQ7uMSQdAiAj+4dzMpJWdSzQ+qGHlHMIBvVHLkqB
y2VdEyF7DPCZewIhAI7GOI/6LDIFOvtPo6Bj2nNmyQ1HU6k/LRtNIXi4c9NJAiAr
rrxx26itVhJmcvoUhOjwuzSlP2bE5VHAvkGB352YBg==
-----END RSA PRIVATE KEY-----`

var rsaKey ssh.Signer
var rawRSAKey *rsa.PrivateKey

func init() {
	block, _ := pem.Decode([]byte(rsaKeySerialized))
	if block == nil {
		panic("ssh: no key found")
	}

	rawRSAKey, _ = x509.ParsePKCS1PrivateKey(block.Bytes)
	rsaKey, _ = ssh.NewSignerFromKey(rawRSAKey)
}

func startAgent(t *testing.T) (client *AgentClient, cleanup func()) {
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

	conn, err := net.Dial("unix", string(socket))
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}

	ac := NewAgentClient(conn)
	return ac, func() {
		proc, _ := os.FindProcess(pid)
		if proc != nil {
			proc.Kill()
		}
		ac.Close()
	}
}

func TestAgent(t *testing.T) {
	agent, cleanup := startAgent(t)
	defer cleanup()
	keys, err := agent.List()
	if err != nil {
		t.Fatalf("RequestIdentities: %v", err)
	}
	if len(keys) > 0 {
		t.Errorf("got %d keys, want 0", len(keys))
	}
	if err := agent.Insert(rawRSAKey, "comment"); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if keys, _ := agent.List(); len(keys) != 1 || keys[0].Comment != "comment" {
		t.Fatalf("got %v, want 1 key with comment `comment`", keys)
	}
	data := []byte("hello")
	sigBytes, err := agent.Sign(rsaKey.PublicKey(), data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	type Sig struct {
		Algo string
		Blob []byte
	}
	sig := Sig{}
	if err := ssh.Unmarshal(sigBytes, &sig); err != nil {
		t.Fatalf("parseSignatureBody(%q) failed", sigBytes)
	}

	if !rsaKey.PublicKey().Verify(data, sig.Blob) {
		t.Fatalf("key signature does not validate")
	}
}

// netPipe is analogous to net.Pipe, but it uses a real net.Conn, and
// therefore is buffered (net.Pipe deadlocks if both sides start with
// a write.)
func netPipe() (net.Conn, net.Conn, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	defer listener.Close()
	c1, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		return nil, nil, err
	}

	c2, err := listener.Accept()
	if err != nil {
		c1.Close()
		return nil, nil, err
	}

	return c1, c2, nil
}

func TestAuth(t *testing.T) {
	a, b, err := netPipe()
	if err != nil {
		t.Fatalf("netPipe: %v", err)
	}

	defer a.Close()
	defer b.Close()

	agent, cleanup := startAgent(t)
	defer cleanup()

	if err := agent.Insert(rawRSAKey, "comment"); err != nil {
		t.Errorf("Insert: %v", err)
	}

	serverConf := ssh.ServerConfig{}
	serverConf.AddHostKey(rsaKey)
	serverConf.PublicKeyCallback = func(c ssh.ConnMetadata, algo string, pubkey []byte) bool {
		return bytes.Equal(pubkey, ssh.MarshalPublicKey(rsaKey.PublicKey()))
	}

	go func() {
		conn, _, _, err := ssh.NewServerConn(a, &serverConf)
		if err != nil {
			t.Fatalf("Server: %v", err)
		}
		conn.Close()
	}()

	conf := ssh.ClientConfig{}
	conf.Auth = append(conf.Auth, ssh.PublicKeysCallback(agent.Signers))
	conn, _, _, err := ssh.NewClientConn(b, "", &conf)
	if err != nil {
		t.Fatalf("NewClientConn: %v", err)
	}
	conn.Close()
}
