# Dedicated R2 resource profile

This experimental profile is dedicated to n-0x R2. General-purpose WireGuard
use is outside its integration contract. Consumer acceptance and measurements
are recorded in x-sys ADR 0012; publishing this dependency alone does not
claim F5 closure or deployment approval.
It preserves the upstream MIT LICENSE, module path and full history from
WireGuard/wireguard-go commit
`b3bc704ef0ee21a36298601a9e1e5ff90377ac52` at
https://github.com/WireGuard/wireguard-go. Its resource implementation is the
previously tested prototype commit `147be93d55d083d79b417361e14a776fd2494d1c`.
This promotion changes platform/test selection and documentation only; resource
values, pool behavior, crypto, wire and lifecycle are unchanged.

## Default selection: no consumer build flags

Linux and Darwin select the R2 profile by default, including its behavioral
tests, without `-tags`. **Android and iOS are expressly excluded**, despite
matching Go's linux/darwin compatibility tags. Other targets preserve their
upstream resource defaults. The explicit `r2resourceprofile` opt-in tag remains
available on those other targets for experiments; it is not required for normal
Linux/Darwin consumption.

| Target without custom tags | Message size | Staged / queues | Prealloc | Cache / workers |
|---|---:|---|---:|---|
| Linux / Darwin |2016|2 /8|0|32 /1 per stage|
| Android |65535|128 /1024|4096|upstream sync.Pool /NumCPU|
| iOS |1700|128 /1024|1024|upstream sync.Pool /NumCPU|
| Windows |2016|128 /1024|0|upstream sync.Pool /NumCPU|
| Other upstream-default targets |65535|128 /1024|0|upstream sync.Pool /NumCPU|

R2 handshake queue8 retains the existing cookie threshold QueueHandshakeSize/8,
so the threshold is1. All five idle caches retain at most32 objects with
nonblocking reuse/create and retain/discard operations; Prealloc0 does not wait
for a borrower. Nil and positive-max WaitPool behavior remain as tested in the
prototype. R2 idle StdNetBind metadata releases payload references. The helper
ChannelBind race fix is inherited unchanged and separate from resource policy.

## Required consumer contract and limits

Use only with the R2 adapter: inner MTU1420, batch8, one peer/device and at most
two ReceiveFuncs, with the documented timer/caller topology. Preserve the two
65535-byte GRO input slots in the compact Bind. A direct general-purpose
Linux StdNetBind receiving into2016-byte arrays cannot safely receive a large
GRO aggregate; this is not a generic wireguard-go binary configuration.

The consumer must reject/drop oversize datagrams **before** copying into the
2016-byte output. The old compact adapter returns short-buffer errors on
2017..2048-byte segments before the outer WG1452 filter; repeated errors may
retire a reader. The peer owner supplies that fix and its regression showing
reader survival followed by valid traffic. It is a prerequisite to integration.

The smaller buffer loses full-MTU TX coalescing:8 WG packets of1452 bytes
produce8 messages, while8 packets of128 bytes can still produce1. No TX staging
was added. The prior offload tests validate real GRO IPv4/IPv6, UDP transit and
the disabled-offload path, not forced NIC EIO recovery or equal CPU cost.

The inherited688-array bound is conditional on the frozen per-device topology
and includes idle message cache and sequential slice references; metadata,
stacks, garbage, kernel memory and retired device graphs are outside it. It is
not an RSS limit. Churn, CPU, throughput and the consumer's full F5 evaluation
remain with their owners. This promotion makes no RSS, performance or F5 claim.

## Verification of this promotion

Run the ordinary suite and race on Darwin with **no custom tags**:

```sh
go test ./... -count=1 -timeout=4m
go test -race ./... -count=1 -timeout=5m
```

Linux real-socket tests use `R2_GRO_TEST=1` as the existing opt-in execution
gate, with `go test -v ./conn -run '^TestR2'` and `go test ./...`, no build tag.
Docker runs use the explicit local Unix endpoint, a local image by ID,
`--pull never --network none`, and read-only source/module mounts.

The selection regression independently derives expected constants from GOOS.
A source/test selection matrix uses `go list -json` for Linux, Darwin, Windows,
Android, iOS and FreeBSD, both defaults and explicit opt-in; it also compares
legacy value definitions to exact upstream and R2 values to the prototype.
Android/iOS checks are source selection only, not target execution. Windows
checks compile device/conn test binaries with `go test -c -o /dev/null`; they
do not execute a foreign target or use a dummy executor. Detailed commands,
results, SHA and freeze evidence are in the external promotion report.

## Versioned consumption and provenance

The dedicated fork is https://github.com/n-0x/wireguard-go. Version
`v0.0.0-r2.1` retains the upstream module path and is consumed with a remote,
versioned replacement, with no consumer build flags on Linux/Darwin:

```sh
go mod edit -replace=golang.zx2c4.com/wireguard=github.com/n-0x/wireguard-go@v0.0.0-r2.1
go mod tidy
```

Use only with the integration contract above and the consumer's oversize
reader-survival regression. The upstream base and MIT license remain in this
repository; cryptographic and wire source is unchanged from that base. Updating
upstream or changing R2 topology/MTU/batch requires revalidating the resource
bound, platform selection, transit, lifecycle and consumer F5 acceptance.
The original candidate evaluation used an external modfile and local replacement;
no local replacement is required by the published consumer.
