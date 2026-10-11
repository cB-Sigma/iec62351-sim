// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package sim is a TLS peer that follows the IEC 62351-3 profile, for
// testing devices and clients: a throw-away PKI, an echo server and a
// client that connects, sends a message and reads it back. Both sides are
// tlsprofile profiles, so they offer only the profile's versions and
// suites, require mutual authentication and record the profile's events.
package sim

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	tls "github.com/cB-Sigma/tlsx"

	"github.com/cB-Sigma/iec62351/tlsprofile"
	"github.com/cB-Sigma/iec62351/tlsprofile/tlsprofiletest"
)

// PKI is a demo CA with one server and one client certificate (ECDSA
// P-256). The server certificate names ServerName and 127.0.0.1.
type PKI struct {
	CA         *tlsprofiletest.CA
	Server     *tlsprofiletest.Issued
	Client     *tlsprofiletest.Issued
	ServerName string
}

// NewPKI makes a PKI for serverName (default "rtu.test").
func NewPKI(serverName string) (*PKI, error) {
	if serverName == "" {
		serverName = "rtu.test"
	}
	ca, err := tlsprofiletest.NewCA("tlsprofilesim root")
	if err != nil {
		return nil, err
	}
	srv, err := ca.Issue(tlsprofiletest.Leaf{Name: serverName, Server: true})
	if err != nil {
		return nil, err
	}
	cli, err := ca.Issue(tlsprofiletest.Leaf{Name: "tlsprofilesim client"})
	if err != nil {
		return nil, err
	}
	return &PKI{CA: ca, Server: srv, Client: cli, ServerName: serverName}, nil
}

// ServerSettings are profile settings for the server certificate.
func (k *PKI) ServerSettings() tlsprofile.Settings {
	return tlsprofile.Settings{CA: k.CA.PEM, Cert: k.Server.CertPEM, Key: k.Server.KeyPEM}
}

// ClientSettings are profile settings for the client certificate,
// checking the server against ServerName.
func (k *PKI) ClientSettings() tlsprofile.Settings {
	return tlsprofile.Settings{CA: k.CA.PEM, Cert: k.Client.CertPEM, Key: k.Client.KeyPEM, ServerName: k.ServerName}
}

// Server is an echo server under a server profile.
type Server struct {
	// Addr is the address it listens on.
	Addr string

	p      *tlsprofile.Profile
	ln     net.Listener
	wg     sync.WaitGroup
	mu     sync.Mutex
	conns  map[net.Conn]bool
	closed bool
	errs   []error
}

// Start listens on addr (for example "127.0.0.1:0") and echoes what each
// client sends, under the profile p (a server profile).
func Start(addr string, p *tlsprofile.Profile) (*Server, error) {
	if p == nil || p.Role() != tlsprofile.Server {
		return nil, errors.New("sim: Start needs a server profile")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s := &Server{Addr: ln.Addr().String(), p: p, ln: ln, conns: map[net.Conn]bool{}}
	s.wg.Add(1)
	go s.accept()
	return s, nil
}

func (s *Server) accept() {
	defer s.wg.Done()
	for {
		raw, err := s.ln.Accept()
		if err != nil {
			return
		}
		c := s.p.Server(raw)
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			c.Close()
			return
		}
		s.conns[c] = true
		s.mu.Unlock()
		s.wg.Add(1)
		go s.serve(c)
	}
}

func (s *Server) serve(c *tlsprofile.Conn) {
	defer s.wg.Done()
	defer func() {
		c.Close()
		s.mu.Lock()
		delete(s.conns, c)
		s.mu.Unlock()
	}()
	if err := c.Handshake(); err != nil {
		s.mu.Lock()
		s.errs = append(s.errs, err)
		s.mu.Unlock()
		return
	}
	io.Copy(c, c)
}

// Errors are the handshakes the server refused, oldest first.
func (s *Server) Errors() []error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]error(nil), s.errs...)
}

// Close stops the server and ends its connections.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	for c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
	err := s.ln.Close()
	s.wg.Wait()
	return err
}

// Result is what a Ping saw.
type Result struct {
	Version     string // "TLS 1.2" or "TLS 1.3"
	CipherSuite string // IANA name
	Echo        []byte
}

// Ping connects to addr with the client profile p, sends msg and reads
// it back.
func Ping(ctx context.Context, p *tlsprofile.Profile, addr string, msg []byte) (Result, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
	}
	c, err := p.Dial(ctx, &net.Dialer{}, addr)
	if err != nil {
		return Result{}, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	if _, err := c.Write(msg); err != nil {
		return Result{}, err
	}
	echo := make([]byte, len(msg))
	if _, err := io.ReadFull(c, echo); err != nil {
		return Result{}, err
	}
	cs := c.ConnectionState()
	return Result{Version: tls.VersionName(cs.Version), CipherSuite: tls.CipherSuiteName(cs.CipherSuite), Echo: echo}, nil
}
