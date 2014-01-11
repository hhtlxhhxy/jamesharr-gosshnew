// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
  Package agent implements a client to an ssh-agent daemon.

References:
  [PROTOCOL.agent]:    http://www.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.agent
*/
package agent

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"

	"code.google.com/p/gosshnew/ssh"
)

// See [PROTOCOL.agent], section 3.
const (
	// 3.2 Requests from client to agent for protocol 2 key operations
	agentRemoveIdentity      = 18
	agentRemoveAllIdentities = 19
	agentAddIdConstrained    = 25

	// 3.3 Key-type independent requests from client to agent
	agentAddSmartcardKey            = 20
	agentRemoveSmartcardKey         = 21
	agentLock                       = 22
	agentUnlock                     = 23
	agentAddSmartcardKeyConstrained = 26

	// 3.7 Key constraint identifiers
	agentConstrainLifetime = 1
	agentConstrainConfirm  = 2
)

// maxAgentResponseBytes is the maximum agent reply size that is accepted. This
// is a sanity check, not a limit in the spec.
const maxAgentResponseBytes = 16 << 20

// Agent messages:
// These structures mirror the wire format of the corresponding ssh agent
// messages found in [PROTOCOL.agent].

// 3.4 Generic replies from agent to client
const agentFailure = 5

type failureAgentMsg struct{}

const agentSuccess = 6

type successAgentMsg struct{}

// See [PROTOCOL.agent], section 2.5.2.
const agentRequestIdentities = 11

type requestIdentitiesAgentMsg struct{}

// See [PROTOCOL.agent], section 2.5.2.
const agentIdentitiesAnswer = 12

type identitiesAnswerAgentMsg struct {
	NumKeys uint32 `sshtype:"12"`
	Keys    []byte `ssh:"rest"`
}

// See [PROTOCOL.agent], section 2.6.2.
const agentSignRequest = 13

type signRequestAgentMsg struct {
	KeyBlob []byte `sshtype:"13"`
	Data    []byte
	Flags   uint32
}

// See [PROTOCOL.agent], section 2.6.2.

// 3.6 Replies from agent to client for protocol 2 key operations
const agentSignResponse = 14

type signResponseAgentMsg struct {
	SigBlob []byte `sshtype:"14"`
}

// AgentKey represents a protocol 2 key as defined in [PROTOCOL.agent],
// section 2.5.2.
type AgentKey struct {
	blob    []byte
	Comment string
}

// String returns the storage form of an agent key with the format, base64
// encoded serialized key, and the comment if it is not empty.
func (ak *AgentKey) String() string {
	k, err := ssh.ParsePublicKey(ak.blob)
	if err != nil {
		return fmt.Sprintf("ssh: malformed key: %v", err)
	}

	s := string(k.PublicKeyAlgo()) + " " + base64.StdEncoding.EncodeToString(ak.blob)

	if ak.Comment != "" {
		s += " " + ak.Comment
	}

	return s
}

// Key returns an agent's public key as one of the supported key or certificate types.
func (ak *AgentKey) Key() (ssh.PublicKey, error) {
	return ssh.ParsePublicKey(ak.blob)
}

func parseAgentKey(in []byte) (out *AgentKey, rest []byte, err error) {
	type parseHelper struct {
		Blob    []byte
		Comment string
		Rest    []byte `ssh:"rest"`
	}

	ak := new(parseHelper)
	if err := ssh.Unmarshal(in, ak); err != nil {
		return nil, nil, err
	}

	return &AgentKey{ak.Blob, ak.Comment}, ak.Rest, nil
}

// AgentClient is a client for an ssh-agent process.
type AgentClient struct {
	// conn is typically represented by using a *net.UnixConn
	conn io.ReadWriteCloser
	// mu is used to prevent concurrent access to the agent
	mu sync.Mutex
}

// NewAgentClient creates and returns a new *AgentClient using the
// passed in io.ReadWriter as a connection to a ssh agent.
func NewAgentClient(rwc io.ReadWriteCloser) *AgentClient {
	return &AgentClient{conn: rwc}
}

// Close closes the connection to the daemon.
func (c *AgentClient) Close() error {
	// Not really needed for network connections, but oh well.
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.Close()
}

// call sends an RPC to the agent. On success, the reply is
// unmarshaled into reply and replyType is set to the first byte of
// the reply, which contains the type of the message.
func (ac *AgentClient) call(req []byte) (reply interface{}, err error) {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	msg := make([]byte, 4+len(req))
	binary.BigEndian.PutUint32(msg, uint32(len(req)))
	copy(msg[4:], req)
	if _, err = ac.conn.Write(msg); err != nil {
		return
	}

	var respSizeBuf [4]byte
	if _, err = io.ReadFull(ac.conn, respSizeBuf[:]); err != nil {
		return
	}
	respSize := binary.BigEndian.Uint32(respSizeBuf[:])
	if respSize > maxAgentResponseBytes {
		err = errors.New("ssh: agent reply too large")
		return
	}

	buf := make([]byte, respSize)
	if _, err = io.ReadFull(ac.conn, buf); err != nil {
		return
	}
	return unmarshal(buf)
}

// List returns the identities known to the agent.
func (ac *AgentClient) List() ([]*AgentKey, error) {
	// see [PROTOCOL.agent] section 2.5.2.
	req := []byte{agentRequestIdentities}

	msg, err := ac.call(req)
	if err != nil {
		return nil, err
	}

	switch msg := msg.(type) {
	case *identitiesAnswerAgentMsg:
		if msg.NumKeys > maxAgentResponseBytes/8 {
			return nil, errors.New("ssh: too many keys in agent reply")
		}
		keys := make([]*AgentKey, msg.NumKeys)
		data := msg.Keys
		for i := uint32(0); i < msg.NumKeys; i++ {
			var key *AgentKey
			var err error
			if key, data, err = parseAgentKey(data); err != nil {
				return nil, err
			}
			keys[i] = key
		}
		return keys, nil
	case *failureAgentMsg:
		return nil, errors.New("ssh: failed to list keys")
	}
	panic("unreachable")
}

// Sign has the agent sign the data using a protocol 2 key as defined
// in [PROTOCOL.agent] section 2.6.2.
func (ac *AgentClient) Sign(key ssh.PublicKey, data []byte) ([]byte, error) {
	req := ssh.Marshal(signRequestAgentMsg{
		KeyBlob: ssh.MarshalPublicKey(key),
		Data:    data,
	})

	msg, err := ac.call(req)
	if err != nil {
		return nil, err
	}

	switch msg := msg.(type) {
	case *signResponseAgentMsg:
		return msg.SigBlob, nil
	case *failureAgentMsg:
		return nil, errors.New("ssh: failed to sign challenge")
	}
	panic("unreachable")
}

// unmarshal parses an agent message in packet, returning the parsed
// form and the message type of packet.
func unmarshal(packet []byte) (interface{}, error) {
	if len(packet) < 1 {
		return nil, ssh.ParseError{0}
	}
	var msg interface{}
	switch packet[0] {
	case agentFailure:
		return new(failureAgentMsg), nil
	case agentSuccess:
		return new(successAgentMsg), nil
	case agentIdentitiesAnswer:
		msg = new(identitiesAnswerAgentMsg)
	case agentSignResponse:
		msg = new(signResponseAgentMsg)
	default:
		return nil, ssh.UnexpectedMessageError{0, packet[0]}
	}
	if err := ssh.Unmarshal(packet, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

const agentAddIdentity = 17

type rsaKeyMsg struct {
	Type     string `sshtype:"17"`
	N        *big.Int
	E        *big.Int
	D        *big.Int
	Iqmp     *big.Int // IQMP = Inverse Q Mod P
	P        *big.Int
	Q        *big.Int
	Comments string
}

// Insert adds a private key to the agent. Currently, only
// *rsa.PrivateKey is supported.
func (ac *AgentClient) Insert(s interface{}, comment string) error {
	switch k := s.(type) {
	case *rsa.PrivateKey:
		req := ssh.Marshal(rsaKeyMsg{
			Type:     ssh.KeyAlgoRSA,
			N:        k.N,
			E:        big.NewInt(int64(k.E)),
			D:        k.D,
			Iqmp:     k.Precomputed.Qinv,
			P:        k.Primes[0],
			Q:        k.Primes[1],
			Comments: comment,
		})
		resp, err := ac.call(req)
		if err != nil {
			return err
		}
		if _, ok := resp.(*successAgentMsg); ok {
			return nil
		}
		return errors.New("ssh: failure")
	}
	return fmt.Errorf("ssh: unsupported key type %T", s)
}

type agentKeyringSigner struct {
	agent *AgentClient
	pub   ssh.PublicKey
}

func (s *agentKeyringSigner) PublicKey() ssh.PublicKey {
	return s.pub
}

func (s *agentKeyringSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	// The agent has its own entropy source, so the rand argument is ignored.
	encoded, err := s.agent.Sign(s.pub, data)
	if err != nil {
		return nil, err
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(encoded, &sig); err != nil {
		return nil, err
	}

	return &sig, nil
}

// Signers implements the ssh.ClientKeyring interface.
func (c *AgentClient) Signers() ([]ssh.Signer, error) {
	keys, err := c.List()
	if err != nil {
		return nil, err
	}

	var result []ssh.Signer
	for _, k := range keys {
		pub, err := k.Key()
		if err != nil {
			// TODO(hanwen): revise this? should never make it into an AgentKey?
			continue
		}
		result = append(result, &agentKeyringSigner{c, pub})
	}
	return result, nil
}
