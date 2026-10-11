// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package sim_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/cB-Sigma/iec62351-sim/sim"
	"github.com/cB-Sigma/iec62351/tlsprofile"
)

func startSim(t *testing.T) (*sim.PKI, *sim.Server) {
	t.Helper()
	k, err := sim.NewPKI("rtu.test")
	if err != nil {
		t.Fatal(err)
	}
	ss := k.ServerSettings()
	sp, err := ss.Server(tlsprofile.Options{Subject: "sim server"})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := sim.Start("127.0.0.1:0", sp)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	return k, srv
}

// TestRefusesOutsideTheProfile: a peer the profile does not allow is
// refused and the refusal is listed by Errors: TLS 1.1, a certificate of
// another CA. A standard crypto/tls client inside the profile is served.
func TestRefusesOutsideTheProfile(t *testing.T) {
	k, srv := startSim(t)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(k.CA.PEM))
	cert, err := tls.X509KeyPair([]byte(k.Client.CertPEM), []byte(k.Client.KeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	dial := func(cfg *tls.Config) error {
		d := &net.Dialer{Timeout: 5 * time.Second}
		c, err := tls.DialWithDialer(d, "tcp", srv.Addr, cfg)
		if err != nil {
			return err
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write([]byte("hi")); err != nil {
			return err
		}
		b := make([]byte, 2)
		_, err = c.Read(b)
		return err
	}
	if err := dial(&tls.Config{RootCAs: pool, ServerName: "rtu.test", Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}); err != nil {
		t.Fatalf("a crypto/tls client inside the profile: %v", err)
	}
	before := len(srv.Errors())
	if err := dial(&tls.Config{RootCAs: pool, ServerName: "rtu.test", Certificates: []tls.Certificate{cert},
		MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}); err == nil {
		t.Error("TLS 1.1 was served")
	}
	other, err := sim.NewPKI("rtu.test")
	if err != nil {
		t.Fatal(err)
	}
	ocert, _ := tls.X509KeyPair([]byte(other.Client.CertPEM), []byte(other.Client.KeyPEM))
	if err := dial(&tls.Config{RootCAs: pool, ServerName: "rtu.test", Certificates: []tls.Certificate{ocert}}); err == nil {
		t.Error("a client certificate of another CA was served")
	}
	deadline := time.Now().Add(3 * time.Second)
	for len(srv.Errors()) < before+2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := len(srv.Errors()) - before; n < 2 {
		t.Errorf("Errors lists %d refusals, want 2", n)
	}
	// Ping with a profile of another PKI fails at the server check too.
	ocs := other.ClientSettings()
	cp, _ := ocs.Client(tlsprofile.Options{Subject: "other"})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := sim.Ping(ctx, cp, srv.Addr, []byte("x")); err == nil {
		t.Error("a client of another PKI was served")
	}
}
