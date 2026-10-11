# iec62351-sim

A TLS peer that follows the IEC 62351-3 profile, in Go, for testing
devices, clients and servers that must speak the profile.

[![Go Reference](https://pkg.go.dev/badge/github.com/cB-Sigma/iec62351-sim.svg)](https://pkg.go.dev/github.com/cB-Sigma/iec62351-sim) [![test](https://github.com/cB-Sigma/iec62351-sim/actions/workflows/test.yml/badge.svg)](https://github.com/cB-Sigma/iec62351-sim/actions/workflows/test.yml) [![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE) [![Go](https://img.shields.io/badge/go-1.27.1-00ADD8.svg)](go.mod)

The simulator has a throw-away PKI (a CA, a server and a client
certificate, ECDSA P-256), an echo server and a client that connects,
sends a message and reads it back. Both sides are profiles of
[iec62351](https://github.com/cB-Sigma/iec62351)'s `tlsprofile`, so
they offer only the profile's versions and suites, require mutual
authentication, renew keys at the profile's interval and record the
profile's security events. Written for SigmaM2M, a oneM2M platform; it
has no dependency on it.

## What is simulated

| Package | What it does |
|---|---|
| `sim` | `NewPKI` (demo CA and certificates), `Start` (an echo server under a server profile; `Errors` lists the handshakes it refused), `Ping` (a client under a client profile: version, suite and the echo) |
| `cmd/tlsprofilesim` | Runs the echo server (with a demo PKI written to `-out`, or with your own certificates) or the client |

It follows IEC 62351-3:2023. Not simulated yet: misbehaving peers (one
that offers TLS 1.1 or suites outside the profile, sends expired,
revoked, oversized or SHA-1 certificates, refuses renegotiation or never
sends KeyUpdate), flags to force a version or suite, RSA, brainpool or
intermediate-CA PKIs (the demo PKI is ECDSA P-256 with one CA), reporting
resumption, renegotiation and KeyUpdate from `Ping`, serving CRLs or
OCSP to an external device from the command (the library's
`tlsprofile/tlsprofiletest` has a CRL source and an OCSP responder for
Go tests), a mapping to the IEC 62351-100-3 test cases, and a device
protocol on top of TLS (the protocol modules have their own simulators).
A device under test is checked against the profile when it connects:
`Server.Errors` lists the handshakes refused.

## Install

```
go get github.com/cB-Sigma/iec62351-sim@latest
go install github.com/cB-Sigma/iec62351-sim/cmd/tlsprofilesim@latest
```

Requires Go 1.27.1 or later.

## Quick start

```
tlsprofilesim -listen 127.0.0.1:3000 -out ./demo-pki
tlsprofilesim -connect 127.0.0.1:3000 -ca demo-pki/ca.pem -cert demo-pki/client.pem -key demo-pki/client.key -name rtu.test
```

In a test:

```go
k, _ := sim.NewPKI("rtu.test")
ss, cs := k.ServerSettings(), k.ClientSettings()
sp, _ := ss.Server(tlsprofile.Options{Subject: "rtu"})
srv, _ := sim.Start("127.0.0.1:0", sp)
defer srv.Close()
cp, _ := cs.Client(tlsprofile.Options{Subject: "scada"})
res, err := sim.Ping(ctx, cp, srv.Addr, []byte("hello")) // res.Version, res.CipherSuite, res.Echo
```

## Testing

```
go vet ./...
go test -race ./...
```

Tests carry `// Covers: SIG-...` comments: requirement IDs of the
SigmaM2M project's compliance report, without meaning outside it.

## Related repositories

- [iec62351](https://github.com/cB-Sigma/iec62351): the TLS profile and
  the other IEC 62351 services.

## Status

v0.x: the API may change before v1. The simulator shares the profile
with the library, so tests against it alone are not independent
evidence; iec62351's interop tests run the profile against OpenSSL.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability privately. The
demo PKI is for tests only.

## Licence

Apache-2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). Copyright 2026
Abhinav Gautam. IEC is a trademark of the International Electrotechnical
Commission; this module is not affiliated with or endorsed by IEC.
