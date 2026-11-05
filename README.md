# rod-listener-doh

The official doh listener package (architecture.md Sec 8, ADR-025 in the
Rod platform repository): the DNS grammar's whole implant ingress,
externalized out of the kernel and answered over the listener bridge.

- the RFC 8484 HTTPS face (`GET /dns-query?dns=<urlsafe-b64>` and
  `POST /dns-query` with an `application/dns-message` body), always TLS
- the classic UDP face (`udp-bind`, the datagram variant)

The payload is one framework-dependent .NET assembly tree under `server/`
(`dotnet server/server.dll`) -- one payload for every (os, arch) cell,
because the kernel host always carries the runtime; Native-AOT single
files ride the edge-host work.

## The medium contract

This is the document an implant author reads to write dial glue -- and it
is the in-tree DNS family's own grammar, unchanged: the TXT-label contact
wire (`p.`, `k.`, `r.`, `e.`, `a.`, and the rest of DnsContactNames' grammar)
under the listener's zone, sealed bodies base32-carried, contacts
identified by implant id alone (the DNS grammar's documented
egress-restricted tradeoff). Nothing about the grammar moved -- the
carriage did: every query, HTTP body or datagram, crosses to the kernel
as one route-forward unit (`POST /dns-query`, the body the DNS wire
message) and the kernel answers with the same DnsContactAnswerer core the
in-tree UDP listener and DoH route drive. Out-of-zone queries are REFUSED
like any resolver refusing to be an open one.

## The process contract

The kernel spawns this process with:

| Variable | Meaning |
|---|---|
| `ROD_BRIDGE_SOCKET` | the kernel's per-listener socket: a Unix domain socket path, or `\\.\pipe\name` on Windows |
| `ROD_LISTENER_ID` | the listener's id |
| `ROD_LISTENER_PARAMS` | the medium parameters as JSON (`udp-bind`, `http-bind`; at least one, or the process exits nonzero -- the exit code is the health signal) |
| `ROD_LISTENER_TLS_PEM` | the engagement CA's server leaf (certificate + PKCS#8 key in one file); the DoH face refuses to serve without it |

The process parses no rod.v1 grammar, holds no engagement key, and learns
no implant identity. The design authority is architecture.md Sec 8 and
ADR-025; the builder's manual is docs/extending/listeners.md in the
platform repository.

## Building and testing

```
./build.sh        # dotnet publish into server/, then the codec self-test
```

The self-test pins the route-forward codec's wire form against the
kernel's own bytes; a publish never rides an unverified codec. `rod mod
publish` packs what `[package] include` names in rod-module.toml -- run
`./build.sh` first so `server/` holds the tree.

## Conformance

`conformance/run.sh` drives the platform repository's official-package e2e
legs against this checkout -- the classic DNS leg over the UDP face, the
Rust reference implant's enroll/contact/task round trip under the zone,
and the wire-level DoH-face leg. It needs a Rod checkout (or an unpacked
source tarball) beside this one. The legs are the conformance evidence,
and they must pass before a release names itself a carrier.
