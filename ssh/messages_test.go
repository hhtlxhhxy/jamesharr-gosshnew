// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"math/big"
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"
)

var intLengthTests = []struct {
	val, length int
}{
	{0, 4 + 0},
	{1, 4 + 1},
	{127, 4 + 1},
	{128, 4 + 2},
	{-1, 4 + 1},
}

func TestIntLength(t *testing.T) {
	for _, test := range intLengthTests {
		v := new(big.Int).SetInt64(int64(test.val))
		length := intLength(v)
		if length != test.length {
			t.Errorf("For %d, got length %d but expected %d", test.val, length, test.length)
		}
	}
}

var messageTypes = []interface{}{
	&kexInitMsg{},
	&kexDHInitMsg{},
	&serviceRequestMsg{},
	&serviceAcceptMsg{},
	&userAuthRequestMsg{},
	&channelOpenMsg{},
	&channelOpenConfirmMsg{},
	&channelOpenFailureMsg{},
	&channelRequestMsg{},
	&channelRequestSuccessMsg{},
}

func TestMarshalUnmarshal(t *testing.T) {
	rand := rand.New(rand.NewSource(0))
	for i, iface := range messageTypes {
		ty := reflect.ValueOf(iface).Type()

		n := 100
		if testing.Short() {
			n = 5
		}
		for j := 0; j < n; j++ {
			v, ok := quick.Value(ty, rand)
			if !ok {
				t.Errorf("#%d: failed to create value", i)
				break
			}

			m1 := v.Elem().Interface()
			m2 := iface

			marshaled := Marshal(m1)
			if err := Unmarshal(marshaled, m2); err != nil {
				t.Errorf("#%d failed to Unmarshal %#v: %s", i, m1, err)
				break
			}

			if !reflect.DeepEqual(v.Interface(), m2) {
				t.Errorf("#%d\ngot: %#v\nwant:%#v\n%x", i, m2, m1, marshaled)
				break
			}
		}
	}
}

func TestUnmarshalEmptyPacket(t *testing.T) {
	var b []byte
	var m channelRequestSuccessMsg
	err := Unmarshal(b, &m)
	want := ParseError{msgChannelSuccess}
	if _, ok := err.(ParseError); !ok {
		t.Fatalf("got %T, want %T", err, want)
	}
	if got := err.(ParseError); want != got {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestUnmarshalUnexpectedPacket(t *testing.T) {
	type S struct {
		I uint32 `sshtype:"43"`
		S string
		B bool
	}

	s := S{11, "hello", true}
	packet := Marshal(s)
	packet[0] = 42
	roundtrip := S{}
	err := Unmarshal(packet, &roundtrip)
	if err == nil {
		t.Fatal("expected error, not nil")
	}
	want := UnexpectedMessageError{43, 42}
	if got, ok := err.(UnexpectedMessageError); !ok || want != got {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestBareMarshalUnmarshal(t *testing.T) {
	type S struct {
		I uint32
		S string
		B bool
	}

	s := S{42, "hello", true}
	packet := Marshal(s)
	roundtrip := S{}
	Unmarshal(packet, &roundtrip)

	if !reflect.DeepEqual(s, roundtrip) {
		t.Errorf("got %#v, want %#v", roundtrip, s)
	}
}

func TestBareMarshal(t *testing.T) {
	type S2 struct {
		I uint32
	}
	s := S2{42}
	packet := Marshal(s)
	i, rest, ok := parseUint32(packet)
	if len(rest) > 0 || !ok {
		t.Errorf("parseInt(%q): parse error", packet)
	}
	if i != s.I {
		t.Errorf("got %d, want %d", i, s.I)
	}
}

func randomBytes(out []byte, rand *rand.Rand) {
	for i := 0; i < len(out); i++ {
		out[i] = byte(rand.Int31())
	}
}

func randomNameList(rand *rand.Rand) []string {
	ret := make([]string, rand.Int31()&15)
	for i := range ret {
		s := make([]byte, 1+(rand.Int31()&15))
		for j := range s {
			s[j] = 'a' + uint8(rand.Int31()&15)
		}
		ret[i] = string(s)
	}
	return ret
}

func randomInt(rand *rand.Rand) *big.Int {
	return new(big.Int).SetInt64(int64(int32(rand.Uint32())))
}

func (*kexInitMsg) Generate(rand *rand.Rand, size int) reflect.Value {
	ki := &kexInitMsg{}
	randomBytes(ki.Cookie[:], rand)
	ki.KexAlgos = randomNameList(rand)
	ki.ServerHostKeyAlgos = randomNameList(rand)
	ki.CiphersClientServer = randomNameList(rand)
	ki.CiphersServerClient = randomNameList(rand)
	ki.MACsClientServer = randomNameList(rand)
	ki.MACsServerClient = randomNameList(rand)
	ki.CompressionClientServer = randomNameList(rand)
	ki.CompressionServerClient = randomNameList(rand)
	ki.LanguagesClientServer = randomNameList(rand)
	ki.LanguagesServerClient = randomNameList(rand)
	if rand.Int31()&1 == 1 {
		ki.FirstKexFollows = true
	}
	return reflect.ValueOf(ki)
}

func (*kexDHInitMsg) Generate(rand *rand.Rand, size int) reflect.Value {
	dhi := &kexDHInitMsg{}
	dhi.X = randomInt(rand)
	return reflect.ValueOf(dhi)
}

// TODO(dfc) maybe this can be removed in the future if testing/quick can handle
// derived basic types.
func (RejectionReason) Generate(rand *rand.Rand, size int) reflect.Value {
	m := RejectionReason(Prohibited)
	return reflect.ValueOf(m)
}

var (
	_kexInitMsg   = new(kexInitMsg).Generate(rand.New(rand.NewSource(0)), 10).Elem().Interface()
	_kexDHInitMsg = new(kexDHInitMsg).Generate(rand.New(rand.NewSource(0)), 10).Elem().Interface()

	_kexInit   = Marshal(_kexInitMsg)
	_kexDHInit = Marshal(_kexDHInitMsg)
)

func BenchmarkMarshalKexInitMsg(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Marshal(_kexInitMsg)
	}
}

func BenchmarkUnmarshalKexInitMsg(b *testing.B) {
	m := new(kexInitMsg)
	for i := 0; i < b.N; i++ {
		Unmarshal(_kexInit, m)
	}
}

func BenchmarkMarshalKexDHInitMsg(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Marshal(_kexDHInitMsg)
	}
}

func BenchmarkUnmarshalKexDHInitMsg(b *testing.B) {
	m := new(kexDHInitMsg)
	for i := 0; i < b.N; i++ {
		Unmarshal(_kexDHInit, m)
	}
}
