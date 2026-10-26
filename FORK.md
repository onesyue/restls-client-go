# YueTo maintenance patch

This fork preserves the module path `github.com/metacubex/restls-client-go` and
the Restls wire protocol. It starts at upstream
[`6566c5f8a24420fbaeb27bc74deea2597a30f4a7`](https://github.com/MetaCubeX/restls-client-go/commit/6566c5f8a24420fbaeb27bc74deea2597a30f4a7)
(`v0.1.9`, 2026-07-20).

## Full-duplex record counters

The client owns its receive counter under `in.Mutex` and its send counter under
`out.Mutex`. Four diagnostic calls accessed the opposite direction's counter.
Function arguments are evaluated even when the diagnostic function's body is
disabled, so concurrent application reads and writes raced.

Diagnostics now read only their own direction's counter. Counter progression,
authentication, record encoding and the separate read/write locks are unchanged.
No additional lock, atomic operation or network buffering is added to production
code.

The regression suite covers actual TLS 1.2/1.3 handshakes and authenticated
bidirectional payloads through both `Conn.Write` and `UConn.Write`. Separate
unbuffered `net.Pipe` tests exercise the native record layers after negotiated
state initialization; this explicitly separates record concurrency from TLS
handshake flights, which assume a buffered stream. A close test observes both
underlying I/O operations and verifies that closing releases them.

With Go 1.26.8, the added regressions report data races on the unpatched upstream
source and pass with this patch:

```sh
GOTOOLCHAIN=go1.26.8 GOMAXPROCS=4 go test -race -count=10 -run '^TestRestlsClient' .
```

Published maintenance versions use signed tags such as `v0.1.10-yueto.1`.
Tags are never moved or reused. Consumers should pin an exact tag and retain
its Go module checksums, or pin its complete commit identity.
