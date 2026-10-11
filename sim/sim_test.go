// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package sim_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/cB-Sigma/iec62351-sim/sim"
	"github.com/cB-Sigma/iec62351/tlsprofile"
	"github.com/cB-Sigma/iec62351/tlsprofile/tlsprofiletest"
)

func TestPingAndRefusal(t *testing.T) {
	k, err := sim.NewPKI("")
	if err != nil {
		t.Fatal(err)
	}
	rec := &tlsprofiletest.Recorder{}
	ss := k.ServerSettings()
	sp, err := ss.Server(tlsprofile.Options{Subject: "sim server", Recorder: rec})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := sim.Start("127.0.0.1:0", sp)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	cs := k.ClientSettings()
	cp, err := cs.Client(tlsprofile.Options{Subject: "sim client", Recorder: rec})
	if err != nil {
		t.Fatal(err)
	}
	r, err := sim.Ping(context.Background(), cp, srv.Addr, []byte("ping"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(r.Echo, []byte("ping")) || r.Version == "" || r.CipherSuite == "" {
		t.Fatalf("result %+v", r)
	}

	// A client without a certificate is refused: the profile needs mutual
	// authentication.
	bare := tlsprofile.Settings{CA: k.CA.PEM, ServerName: k.ServerName}
	bp, err := bare.Client(tlsprofile.Options{Subject: "bare client", Recorder: rec})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sim.Ping(context.Background(), bp, srv.Addr, []byte("x")); err == nil {
		t.Fatal("a client without a certificate was served")
	}
}
