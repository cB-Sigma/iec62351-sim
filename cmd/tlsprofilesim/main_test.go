// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cB-Sigma/iec62351-sim/sim"
	"github.com/cB-Sigma/iec62351/tlsprofile"
)

func TestClientAgainstDemoServer(t *testing.T) {
	k, err := sim.NewPKI("")
	if err != nil {
		t.Fatal(err)
	}
	ss := k.ServerSettings()
	p, err := ss.Server(tlsprofile.Options{Subject: "test"})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := sim.Start("127.0.0.1:0", p)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	dir := t.TempDir()
	files := map[string]string{"ca.pem": k.CA.PEM, "client.pem": k.Client.CertPEM, "client.key": k.Client.KeyPEM}
	for f, v := range files {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	err = run("", srv.Addr, filepath.Join(dir, "ca.pem"), filepath.Join(dir, "client.pem"), filepath.Join(dir, "client.key"), k.ServerName, "", "hello")
	if err != nil {
		t.Fatal(err)
	}
}
