// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Command tlsprofilesim runs a TLS echo server under the IEC 62351-3
// profile, or connects to one, for testing devices and clients.
//
//	tlsprofilesim -listen 127.0.0.1:3000 -out ./demo-pki
//	tlsprofilesim -connect 127.0.0.1:3000 -ca demo-pki/ca.pem -cert demo-pki/client.pem -key demo-pki/client.key -name rtu.test
//
// Without -cert and -key the server makes a demo PKI and, with -out,
// writes its CA and a client certificate and key there.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/cB-Sigma/iec62351-sim/sim"
	"github.com/cB-Sigma/iec62351/tlsprofile"
)

func main() {
	listen := flag.String("listen", "", "serve on this address")
	connect := flag.String("connect", "", "connect to this address and send -msg")
	ca := flag.String("ca", "", "trust anchors (PEM file)")
	cert := flag.String("cert", "", "own certificate (PEM file)")
	key := flag.String("key", "", "own key (PEM file)")
	name := flag.String("name", "", "server name to check (client) or to put in the demo certificate (server)")
	out := flag.String("out", "", "server with a demo PKI: write ca.pem, client.pem and client.key here")
	msg := flag.String("msg", "ping", "message to send (client)")
	flag.Parse()
	if err := run(*listen, *connect, *ca, *cert, *key, *name, *out, *msg); err != nil {
		log.Fatal(err)
	}
}

func read(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	b, err := os.ReadFile(path)
	return string(b), err
}

func run(listen, connect, caFile, certFile, keyFile, name, out, msg string) error {
	o := tlsprofile.Options{Subject: "tlsprofilesim", Log: slog.Default()}
	ca, err := read(caFile)
	if err != nil {
		return err
	}
	cert, err := read(certFile)
	if err != nil {
		return err
	}
	key, err := read(keyFile)
	if err != nil {
		return err
	}
	switch {
	case connect != "":
		s := tlsprofile.Settings{CA: ca, Cert: cert, Key: key, ServerName: name}
		p, err := s.Client(o)
		if err != nil {
			return err
		}
		r, err := sim.Ping(context.Background(), p, connect, []byte(msg))
		if err != nil {
			return err
		}
		fmt.Printf("%s %s echo %q\n", r.Version, r.CipherSuite, r.Echo)
		return nil
	case listen != "":
		s := tlsprofile.Settings{CA: ca, Cert: cert, Key: key}
		if cert == "" || key == "" {
			k, err := sim.NewPKI(name)
			if err != nil {
				return err
			}
			s = k.ServerSettings()
			if out != "" {
				if err := os.MkdirAll(out, 0o700); err != nil {
					return err
				}
				for f, v := range map[string]string{"ca.pem": k.CA.PEM, "client.pem": k.Client.CertPEM, "client.key": k.Client.KeyPEM} {
					if err := os.WriteFile(filepath.Join(out, f), []byte(v), 0o600); err != nil {
						return err
					}
				}
			}
			fmt.Printf("demo PKI: server name %s\n", k.ServerName)
		}
		p, err := s.Server(o)
		if err != nil {
			return err
		}
		srv, err := sim.Start(listen, p)
		if err != nil {
			return err
		}
		fmt.Printf("listening on %s\n", srv.Addr)
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt)
		<-sig
		return srv.Close()
	}
	return fmt.Errorf("give -listen or -connect")
}
