# Provenance

Written for SigmaM2M, a oneM2M platform, in Go, by the author of the
iec62351 module, on 2026-10-06, as a profile-conformant peer for the
tests of the IEC 62351-3 profile (IEC 62351-3:2023, read in a licensed
copy; no text of it is reproduced). No code was ported or copied from
another implementation. The simulator and its command moved out of the
iec62351 module into this one on 2026-10-11 (with `git mv`), so the
library does not depend on its simulator. Flags and demo names are our
own; every key is generated at run time.

`// Covers:` lines in the tests name SigmaM2M requirement rows and mean
nothing outside SigmaM2M's compliance report.
