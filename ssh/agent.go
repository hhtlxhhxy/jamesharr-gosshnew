// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
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
	algo, _, ok := parseString(ak.blob)
	if !ok {
		return "ssh: malformed key"
	}

	s := string(algo) + " " + base64.StdEncoding.EncodeToString(ak.blob)

	if ak.Comment != "" {
		s += " " + ak.Comment
	}

	return s
}

// Key returns an agent's public key as one of the supported key or certificate types.
func (ak *AgentKey) Key() (PublicKey, error) {
	if key, _, ok := ParsePublicKey(ak.blob); ok {
		return key, nil
	}
	return nil, errors.New("ssh: failed to parse key blob")
}

func parseAgentKey(in []byte) (out *AgentKey, rest []byte, ok bool) {
	ak := new(AgentKey)

	if ak.blob, in, ok = parseString(in); !ok {
		return
	}

	comment, in, ok := parseString(in)
	if !ok {
		return
	}
	ak.Comment = string(comment)

	return ak, in, true
}

// AgentClient provides a means to communicate with an ssh agent process based
// on the protocol described in [PROTOCOL.agent]?rev=1.6.
type AgentClient struct {
	// conn is typically represented by using a *net.UnixConn
	conn io.ReadWriter
	// mu is used to prevent concurrent access to the agent
	mu sync.Mutex
}

// NewAgentClient creates and returns a new *AgentClient using the
// passed in io.ReadWriter as a connection to a ssh agent.
func NewAgentClient(rw io.ReadWriter) *AgentClient {
	return &AgentClient{conn: rw}
}

// sendAndReceive sends req to the agent and waits for a reply. On success,
// the reply is unmarshaled into reply and replyType is set to the first byte of
// the reply, which contains the type of the message.
func (ac *AgentClient) sendAndReceive(req []byte) (reply interface{}, err error) {
	// ac.mu prevents multiple, concurrent requests. Since the agent is typically
	// on the same machine, we don't attempt to pipeline the requests.
	ac.mu.Lock()
	defer ac.mu.Unlock()

	msg := make([]byte, stringLength(len(req)))
	marshalString(msg, req)
	if _, err = ac.conn.Write(msg); err != nil {
		return
	}

	var respSizeBuf [4]byte
	if _, err = io.ReadFull(ac.conn, respSizeBuf[:]); err != nil {
		return
	}
	respSize, _, _ := parseUint32(respSizeBuf[:])

	if respSize > maxAgentResponseBytes {
		err = errors.New("ssh: agent reply too large")
		return
	}

	buf := make([]byte, respSize)
	if _, err = io.ReadFull(ac.conn, buf); err != nil {
		return
	}
	return unmarshalAgentMsg(buf)
}

// RequestIdentities queries the agent for protocol 2 keys as defined in
// [PROTOCOL.agent] section 2.5.2.
func (ac *AgentClient) RequestIdentities() ([]*AgentKey, error) {
	req := []byte{agentRequestIdentities}

	msg, err := ac.sendAndReceive(req)
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
			var ok bool
			if key, data, ok = parseAgentKey(data); !ok {
				return nil, ParseError{agentIdentitiesAnswer}
			}
			keys[i] = key
		}
		return keys, nil
	case *failureAgentMsg:
		return nil, errors.New("ssh: failed to list keys")
	}
	panic("unreachable")
}

// SignRequest requests the signing of data by the agent using a protocol 2 key
// as defined in [PROTOCOL.agent] section 2.6.2.
func (ac *AgentClient) SignRequest(key PublicKey, data []byte) ([]byte, error) {
	req := Marshal(signRequestAgentMsg{
		KeyBlob: MarshalPublicKey(key),
		Data:    data,
	})

	msg, err := ac.sendAndReceive(req)
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

// unmarshalAgentMsg parses an agent message in packet, returning the parsed
// form and the message type of packet.
func unmarshalAgentMsg(packet []byte) (interface{}, error) {
	if len(packet) < 1 {
		return nil, ParseError{0}
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
		return nil, UnexpectedMessageError{0, packet[0]}
	}
	if err := Unmarshal(packet, msg); err != nil {
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

func (ac *AgentClient) insert(s Signer, comment string) error {
	switch k := s.(type) {
	case *rsaPrivateKey:
		req := Marshal(rsaKeyMsg{
			Type:     KeyAlgoRSA,
			N:        k.N,
			E:        big.NewInt(int64(k.E)),
			D:        k.D,
			Iqmp:     k.Precomputed.Qinv,
			P:        k.Primes[0],
			Q:        k.Primes[1],
			Comments: comment,
		})
		resp, err := ac.sendAndReceive(req)
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
