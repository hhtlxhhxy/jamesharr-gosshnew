// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build darwin freebsd linux netbsd openbsd

package test

import (
	"code.google.com/p/gosshnew/ssh"
	"testing"
)

func TestCertLogin(t *testing.T) {
	s := newServer(t)
	defer s.Shutdown()

	// Use a key different from the default.
	clientKey, err := ssh.ParsePrivateKey([]byte(keys["ssh_host_dsa_key"]))
	if err != nil {
		t.Fatalf("ParsePrivateKey(%q): %v", "ssh_host_dsa_key", err)
	}
	caAuthKey, err := ssh.ParsePrivateKey([]byte(keys["user_ca"]))
	if err != nil {
		t.Fatalf("ParsePrivateKey(%q): %v", "user_ca", err)
	}
	cert := &ssh.OpenSSHCertV01{
		Key:             clientKey.PublicKey(),
		ValidPrincipals: []string{username()},
		Type:            ssh.UserCert,
		ValidBefore:     ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(caAuthKey); err != nil {
		t.Fatalf("SetSignature: %v", err)
	}

	certSigner, err := ssh.NewCertSigner(cert, clientKey)
	if err != nil {
		t.Fatalf("NewCertSigner: %v", err)
	}

	conf := &ssh.ClientConfig{
		User: username(),
	}
	conf.Auth = append(conf.Auth, ssh.PublicKeys(certSigner))
	client, err := s.TryDial(conf)
	if err != nil {
		t.Fatalf("TryDial: %v", err)
	}
	client.Close()
}
