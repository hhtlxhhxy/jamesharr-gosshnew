// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/big"
	"reflect"
	"strconv"
)

// These are SSH message type numbers. They are scattered around several
// documents but many were taken from [SSH-PARAMETERS].
const (
	msgIgnore        = 2
	msgUnimplemented = 3
	msgDebug         = 4
	msgNewKeys       = 21

	// Standard authentication messages
	msgUserAuthSuccess = 52
	msgUserAuthBanner  = 53
)

// SSH messages:
//
// These structures mirror the wire format of the corresponding SSH messages.
// They are marshaled using reflection with the marshal and unmarshal functions
// in this file. The only wrinkle is that a final member of type []byte with a
// ssh tag of "rest" receives the remainder of a packet when unmarshaling.

// See RFC 4253, section 11.1.
const msgDisconnect = 1

type disconnectMsg struct {
	Reason   uint32 `sshtype:"1"`
	Message  string
	Language string
}

// See RFC 4253, section 7.1.
const msgKexInit = 20

type kexInitMsg struct {
	Cookie                  [16]byte `sshtype:"20"`
	KexAlgos                []string
	ServerHostKeyAlgos      []string
	CiphersClientServer     []string
	CiphersServerClient     []string
	MACsClientServer        []string
	MACsServerClient        []string
	CompressionClientServer []string
	CompressionServerClient []string
	LanguagesClientServer   []string
	LanguagesServerClient   []string
	FirstKexFollows         bool
	Reserved                uint32
}

// See RFC 4253, section 8.

// Diffie-Helman
const msgKexDHInit = 30

type kexDHInitMsg struct {
	X *big.Int `sshtype:"30"`
}

const msgKexECDHInit = 30

type kexECDHInitMsg struct {
	ClientPubKey []byte `sshtype:"30"`
}

const msgKexECDHReply = 31

type kexECDHReplyMsg struct {
	HostKey         []byte `sshtype:"31"`
	EphemeralPubKey []byte
	Signature       []byte
}

const msgKexDHReply = 31

type kexDHReplyMsg struct {
	HostKey   []byte `sshtype:"31"`
	Y         *big.Int
	Signature []byte
}

// See RFC 4253, section 10.
const msgServiceRequest = 5

type serviceRequestMsg struct {
	Service string `sshtype:"5"`
}

// See RFC 4253, section 10.
const msgServiceAccept = 6

type serviceAcceptMsg struct {
	Service string `sshtype:"6"`
}

// See RFC 4252, section 5.
const msgUserAuthRequest = 50

type userAuthRequestMsg struct {
	User    string `sshtype:"50"`
	Service string
	Method  string
	Payload []byte `ssh:"rest"`
}

// See RFC 4252, section 5.1
const msgUserAuthFailure = 51

type userAuthFailureMsg struct {
	Methods        []string `sshtype:"51"`
	PartialSuccess bool
}

// See RFC 4256, section 3.2
const msgUserAuthInfoRequest = 60
const msgUserAuthInfoResponse = 61

type userAuthInfoRequestMsg struct {
	User               string `sshtype:"60"`
	Instruction        string
	DeprecatedLanguage string
	NumPrompts         uint32
	Prompts            []byte `ssh:"rest"`
}

// See RFC 4254, section 5.1.
const msgChannelOpen = 90

type channelOpenMsg struct {
	ChanType         string `sshtype:"90"`
	PeersId          uint32
	PeersWindow      uint32
	MaxPacketSize    uint32
	TypeSpecificData []byte `ssh:"rest"`
}

const msgChannelExtendedData = 95
const msgChannelData = 94

// See RFC 4254, section 5.1.
const msgChannelOpenConfirm = 91

type channelOpenConfirmMsg struct {
	PeersId          uint32 `sshtype:"91"`
	MyId             uint32
	MyWindow         uint32
	MaxPacketSize    uint32
	TypeSpecificData []byte `ssh:"rest"`
}

// See RFC 4254, section 5.1.
const msgChannelOpenFailure = 92

type channelOpenFailureMsg struct {
	PeersId  uint32 `sshtype:"92"`
	Reason   RejectionReason
	Message  string
	Language string
}

const msgChannelRequest = 98

type channelRequestMsg struct {
	PeersId             uint32 `sshtype:"98"`
	Request             string
	WantReply           bool
	RequestSpecificData []byte `ssh:"rest"`
}

// See RFC 4254, section 5.4.
const msgChannelSuccess = 99

type channelRequestSuccessMsg struct {
	PeersId uint32 `sshtype:"99"`
}

// See RFC 4254, section 5.4.
const msgChannelFailure = 100

type channelRequestFailureMsg struct {
	PeersId uint32 `sshtype:"100"`
}

// See RFC 4254, section 5.3
const msgChannelClose = 97

type channelCloseMsg struct {
	PeersId uint32 `sshtype:"97"`
}

// See RFC 4254, section 5.3
const msgChannelEOF = 96

type channelEOFMsg struct {
	PeersId uint32 `sshtype:"96"`
}

// See RFC 4254, section 4
const msgGlobalRequest = 80

type globalRequestMsg struct {
	Type      string `sshtype:"80"`
	WantReply bool
	Data      []byte `ssh:"rest"`
}

// See RFC 4254, section 4
const msgRequestSuccess = 81

type globalRequestSuccessMsg struct {
	Data []byte `ssh:"rest" sshtype:"81"`
}

// See RFC 4254, section 4
const msgRequestFailure = 82

type globalRequestFailureMsg struct {
	Data []byte `ssh:"rest" sshtype:"82"`
}

// See RFC 4254, section 5.2
const msgChannelWindowAdjust = 93

type windowAdjustMsg struct {
	PeersId         uint32 `sshtype:"93"`
	AdditionalBytes uint32
}

// See RFC 4252, section 7
const msgUserAuthPubKeyOk = 60

type userAuthPubKeyOkMsg struct {
	Algo   string `sshtype:"60"`
	PubKey string
}

// typeTag returns the type byte for the given type. The type should
// be struct.
func typeTag(structType reflect.Type) byte {
	var tag byte
	var tagStr string
	tagStr = structType.Field(0).Tag.Get("sshtype")
	i, err := strconv.Atoi(tagStr)
	if err == nil {
		tag = byte(i)
	}
	return tag
}

// unmarshal parses the SSH wire data in packet into out using
// reflection. unmarshal either returns nil on success, or a
// ParseError or UnexpectedMessageError on error.
func unmarshal(out interface{}, packet []byte) error {
	v := reflect.ValueOf(out).Elem()
	structType := v.Type()
	expectedType := typeTag(structType)
	if len(packet) == 0 {
		return ParseError{expectedType}
	}
	if expectedType > 0 {
		if packet[0] != expectedType {
			return UnexpectedMessageError{expectedType, packet[0]}
		}
		packet = packet[1:]
	}

	var ok bool
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		t := field.Type()
		switch t.Kind() {
		case reflect.Bool:
			if len(packet) < 1 {
				return ParseError{expectedType}
			}
			field.SetBool(packet[0] != 0)
			packet = packet[1:]
		case reflect.Array:
			if t.Elem().Kind() != reflect.Uint8 {
				panic("array of non-uint8")
			}
			if len(packet) < t.Len() {
				return ParseError{expectedType}
			}
			for j, n := 0, t.Len(); j < n; j++ {
				field.Index(j).Set(reflect.ValueOf(packet[j]))
			}
			packet = packet[t.Len():]
		case reflect.Uint32:
			var u32 uint32
			if u32, packet, ok = parseUint32(packet); !ok {
				return ParseError{expectedType}
			}
			field.SetUint(uint64(u32))
		case reflect.String:
			var s []byte
			if s, packet, ok = parseString(packet); !ok {
				return ParseError{expectedType}
			}
			field.SetString(string(s))
		case reflect.Slice:
			switch t.Elem().Kind() {
			case reflect.Uint8:
				if structType.Field(i).Tag.Get("ssh") == "rest" {
					field.Set(reflect.ValueOf(packet))
					packet = nil
				} else {
					var s []byte
					if s, packet, ok = parseString(packet); !ok {
						return ParseError{expectedType}
					}
					field.Set(reflect.ValueOf(s))
				}
			case reflect.String:
				var nl []string
				if nl, packet, ok = parseNameList(packet); !ok {
					return ParseError{expectedType}
				}
				field.Set(reflect.ValueOf(nl))
			default:
				panic("slice of unknown type")
			}
		case reflect.Ptr:
			if t == bigIntType {
				var n *big.Int
				if n, packet, ok = parseInt(packet); !ok {
					return ParseError{expectedType}
				}
				field.Set(reflect.ValueOf(n))
			} else {
				panic("pointer to unknown type")
			}
		default:
			panic("unknown type")
		}
	}

	if len(packet) != 0 {
		return ParseError{expectedType}
	}

	return nil
}

// marshal serializes the message in msg.
func marshal(msg interface{}) []byte {
	out := make([]byte, 0, 64)
	v := reflect.ValueOf(msg)
	msgType := typeTag(v.Type())
	if msgType > 0 {
		out = append(out, msgType)
	}

	for i, n := 0, v.NumField(); i < n; i++ {
		field := v.Field(i)
		switch t := field.Type(); t.Kind() {
		case reflect.Bool:
			var v uint8
			if field.Bool() {
				v = 1
			}
			out = append(out, v)
		case reflect.Array:
			if t.Elem().Kind() != reflect.Uint8 {
				panic("array of non-uint8")
			}
			for j, l := 0, t.Len(); j < l; j++ {
				out = append(out, uint8(field.Index(j).Uint()))
			}
		case reflect.Uint32:
			out = appendU32(out, uint32(field.Uint()))
		case reflect.String:
			s := field.String()
			out = appendInt(out, len(s))
			out = append(out, s...)
		case reflect.Slice:
			switch t.Elem().Kind() {
			case reflect.Uint8:
				if v.Type().Field(i).Tag.Get("ssh") != "rest" {
					out = appendInt(out, field.Len())
				}
				out = append(out, field.Bytes()...)
			case reflect.String:
				offset := len(out)
				out = appendU32(out, 0)
				if n := field.Len(); n > 0 {
					for j := 0; j < n; j++ {
						f := field.Index(j)
						if j != 0 {
							out = append(out, ',')
						}
						out = append(out, f.String()...)
					}
					// overwrite length value
					binary.BigEndian.PutUint32(out[offset:], uint32(len(out)-offset-4))
				}
			default:
				panic("slice of unknown type")
			}
		case reflect.Ptr:
			if t == bigIntType {
				var n *big.Int
				nValue := reflect.ValueOf(&n)
				nValue.Elem().Set(field)
				needed := intLength(n)
				oldLength := len(out)

				if cap(out)-len(out) < needed {
					newOut := make([]byte, len(out), 2*(len(out)+needed))
					copy(newOut, out)
					out = newOut
				}
				out = out[:oldLength+needed]
				marshalInt(out[oldLength:], n)
			} else {
				panic("pointer to unknown type")
			}
		}
	}

	return out
}

var bigOne = big.NewInt(1)

func parseString(in []byte) (out, rest []byte, ok bool) {
	if len(in) < 4 {
		return
	}
	length := binary.BigEndian.Uint32(in)
	if uint32(len(in)) < 4+length {
		return
	}
	out = in[4 : 4+length]
	rest = in[4+length:]
	ok = true
	return
}

var (
	comma         = []byte{','}
	emptyNameList = []string{}
)

func parseNameList(in []byte) (out []string, rest []byte, ok bool) {
	contents, rest, ok := parseString(in)
	if !ok {
		return
	}
	if len(contents) == 0 {
		out = emptyNameList
		return
	}
	parts := bytes.Split(contents, comma)
	out = make([]string, len(parts))
	for i, part := range parts {
		out[i] = string(part)
	}
	return
}

func parseInt(in []byte) (out *big.Int, rest []byte, ok bool) {
	contents, rest, ok := parseString(in)
	if !ok {
		return
	}
	out = new(big.Int)

	if len(contents) > 0 && contents[0]&0x80 == 0x80 {
		// This is a negative number
		notBytes := make([]byte, len(contents))
		for i := range notBytes {
			notBytes[i] = ^contents[i]
		}
		out.SetBytes(notBytes)
		out.Add(out, bigOne)
		out.Neg(out)
	} else {
		// Positive number
		out.SetBytes(contents)
	}
	ok = true
	return
}

func parseUint32(in []byte) (uint32, []byte, bool) {
	if len(in) < 4 {
		return 0, nil, false
	}
	return binary.BigEndian.Uint32(in), in[4:], true
}

func parseUint64(in []byte) (uint64, []byte, bool) {
	if len(in) < 8 {
		return 0, nil, false
	}
	return binary.BigEndian.Uint64(in), in[8:], true
}

func nameListLength(namelist []string) int {
	length := 4 /* uint32 length prefix */
	for i, name := range namelist {
		if i != 0 {
			length++ /* comma */
		}
		length += len(name)
	}
	return length
}

func intLength(n *big.Int) int {
	length := 4 /* length bytes */
	if n.Sign() < 0 {
		nMinus1 := new(big.Int).Neg(n)
		nMinus1.Sub(nMinus1, bigOne)
		bitLen := nMinus1.BitLen()
		if bitLen%8 == 0 {
			// The number will need 0xff padding
			length++
		}
		length += (bitLen + 7) / 8
	} else if n.Sign() == 0 {
		// A zero is the zero length string
	} else {
		bitLen := n.BitLen()
		if bitLen%8 == 0 {
			// The number will need 0x00 padding
			length++
		}
		length += (bitLen + 7) / 8
	}

	return length
}

func marshalUint32(to []byte, n uint32) []byte {
	binary.BigEndian.PutUint32(to, n)
	return to[4:]
}

func marshalUint64(to []byte, n uint64) []byte {
	binary.BigEndian.PutUint64(to, n)
	return to[8:]
}

func marshalInt(to []byte, n *big.Int) []byte {
	lengthBytes := to
	to = to[4:]
	length := 0

	if n.Sign() < 0 {
		// A negative number has to be converted to two's-complement
		// form. So we'll subtract 1 and invert. If the
		// most-significant-bit isn't set then we'll need to pad the
		// beginning with 0xff in order to keep the number negative.
		nMinus1 := new(big.Int).Neg(n)
		nMinus1.Sub(nMinus1, bigOne)
		bytes := nMinus1.Bytes()
		for i := range bytes {
			bytes[i] ^= 0xff
		}
		if len(bytes) == 0 || bytes[0]&0x80 == 0 {
			to[0] = 0xff
			to = to[1:]
			length++
		}
		nBytes := copy(to, bytes)
		to = to[nBytes:]
		length += nBytes
	} else if n.Sign() == 0 {
		// A zero is the zero length string
	} else {
		bytes := n.Bytes()
		if len(bytes) > 0 && bytes[0]&0x80 != 0 {
			// We'll have to pad this with a 0x00 in order to
			// stop it looking like a negative number.
			to[0] = 0
			to = to[1:]
			length++
		}
		nBytes := copy(to, bytes)
		to = to[nBytes:]
		length += nBytes
	}

	lengthBytes[0] = byte(length >> 24)
	lengthBytes[1] = byte(length >> 16)
	lengthBytes[2] = byte(length >> 8)
	lengthBytes[3] = byte(length)
	return to
}

func writeInt(w io.Writer, n *big.Int) {
	length := intLength(n)
	buf := make([]byte, length)
	marshalInt(buf, n)
	w.Write(buf)
}

func writeString(w io.Writer, s []byte) {
	var lengthBytes [4]byte
	lengthBytes[0] = byte(len(s) >> 24)
	lengthBytes[1] = byte(len(s) >> 16)
	lengthBytes[2] = byte(len(s) >> 8)
	lengthBytes[3] = byte(len(s))
	w.Write(lengthBytes[:])
	w.Write(s)
}

func stringLength(n int) int {
	return 4 + n
}

func marshalString(to []byte, s []byte) []byte {
	to[0] = byte(len(s) >> 24)
	to[1] = byte(len(s) >> 16)
	to[2] = byte(len(s) >> 8)
	to[3] = byte(len(s))
	to = to[4:]
	copy(to, s)
	return to[len(s):]
}

var bigIntType = reflect.TypeOf((*big.Int)(nil))

// Decode a packet into its corresponding message.
func decode(packet []byte) (interface{}, error) {
	var msg interface{}
	switch packet[0] {
	case msgDisconnect:
		msg = new(disconnectMsg)
	case msgServiceRequest:
		msg = new(serviceRequestMsg)
	case msgServiceAccept:
		msg = new(serviceAcceptMsg)
	case msgKexInit:
		msg = new(kexInitMsg)
	case msgKexDHInit:
		msg = new(kexDHInitMsg)
	case msgKexDHReply:
		msg = new(kexDHReplyMsg)
	case msgUserAuthRequest:
		msg = new(userAuthRequestMsg)
	case msgUserAuthFailure:
		msg = new(userAuthFailureMsg)
	case msgUserAuthPubKeyOk:
		msg = new(userAuthPubKeyOkMsg)
	case msgGlobalRequest:
		msg = new(globalRequestMsg)
	case msgRequestSuccess:
		msg = new(globalRequestSuccessMsg)
	case msgRequestFailure:
		msg = new(globalRequestFailureMsg)
	case msgChannelOpen:
		msg = new(channelOpenMsg)
	case msgChannelOpenConfirm:
		msg = new(channelOpenConfirmMsg)
	case msgChannelOpenFailure:
		msg = new(channelOpenFailureMsg)
	case msgChannelWindowAdjust:
		msg = new(windowAdjustMsg)
	case msgChannelEOF:
		msg = new(channelEOFMsg)
	case msgChannelClose:
		msg = new(channelCloseMsg)
	case msgChannelRequest:
		msg = new(channelRequestMsg)
	case msgChannelSuccess:
		msg = new(channelRequestSuccessMsg)
	case msgChannelFailure:
		msg = new(channelRequestFailureMsg)
	default:
		return nil, UnexpectedMessageError{0, packet[0]}
	}
	if err := unmarshal(msg, packet); err != nil {
		return nil, err
	}
	return msg, nil
}
