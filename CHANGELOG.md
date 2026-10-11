# Changelog

## v0.1.0 (unreleased)

First public release: the IEC 62351-3 TLS peer (`sim`,
`cmd/tlsprofilesim`) moved out of the iec62351 module with its tests.
New test: peers outside the profile (TLS 1.1, a certificate of another
CA) are refused and listed by `Server.Errors`; a standard crypto/tls
client inside the profile is served.
