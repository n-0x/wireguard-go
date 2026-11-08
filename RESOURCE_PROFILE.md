# R2 structural resource profile prototype

This is an unpublished, reversible prototype based exactly on WireGuard/wireguard-go
commit `b3bc704ef0ee21a36298601a9e1e5ff90377ac52` from
https://github.com/WireGuard/wireguard-go. The upstream MIT LICENSE, module path,
go.mod/go.sum and cryptographic/protocol source files are preserved.

Enable with `-tags=r2resourceprofile`. Without that tag all original platform
constants, worker selection, sync.Pool behavior and socket metadata retention
remain unchanged. The ChannelBind test-helper synchronization fix is separate
from the resource policy and is exercised by upstream TestUpDown under race.

## Profile and integration contract

The profile uses 2016-byte message arrays, staged2, inbound/outbound/crypto8,
handshake8 (the existing QueueHandshakeSize/8 cookie threshold becomes1),
one worker per crypto/handshake stage, and PreallocatedBuffersPerPool=0.
All five WaitPools retain at most32 idle objects in a nonblocking channel.
Get reuses or creates; Put retains or discards; nil behavior and positive-max
WaitPool semantics are preserved. There is no new wait for pool capacity.
Idle StdNetBind message metadata releases its payload references under the tag.
No new allocator/admission API, crypto, wire, syscall or TX staging is introduced.

Only evaluate with the R2 adapter: one peer per device, at most two keepalive
timer callbacks, batch8, inner MTU1420 and the compact Bind preserving full-size
GRO input slots. This is not a general wireguard-go binary configuration.
A direct Linux StdNetBind with small receive buffers cannot safely receive a
large GRO aggregate. A larger MTU is outside this profile's contract.

**Integration prerequisite:** the current R2 compact adapter must reject/drop
oversize segments before copying into upstream's2016-byte output. Its existing
short-buffer error can otherwise retire a ReceiveIncoming reader after repeated
2017..2048-byte datagrams, before wgBind's outer1452-byte filter. That fix belongs
to the peer owner, not this clone; do not use this profile as release evidence
without its reader-survival regression.

## Cota: arrays, not RSS

For the frozen R2 topology, conservatively bound outstanding message arrays by
640 per device: queues/active consumers38B, scratch/private maps6B, up to seven
Stage/SendStaged callers with four temporary containers each28B, cleanup6B,
plus11 handshake and5 keepalive slots, with B=8. Seven callers overcount TUN,
sequential RX, handshake, two serialized keepalive timer types, IPC and Up.
The proof assumes no additional external callers or retired peer graphs.

Add16 arrays retained by the backing slices of the sequential TX/RX routines
after Put and32 arrays in the message cache: at most688 reachable2016-byte
arrays per device under these assumptions. Clearing idle socket metadata is
necessary: otherwise its sync.Pool can retain discarded message arrays outside
this accounting. All five caches individually retain at most32 objects; their
metadata, stacks, other caches, uncollected garbage and kernel sockets are not
included in the array bound.

688*2016 =1387008 bytes/device. Rounding each array to2KiB gives43MiB for32
devices; Linux compact GRO staging adds about23.75MiB, total~66.75MiB for these
two components. This is not an RSS limit. Under churn, Close does not explicitly
join every crypto worker/finalizer, so multiplying by32 also requires bounding
retired graphs separately. No performance or F5 closure is claimed.

## Offload result and validation

Native Darwin full upstream suite passed with and without the tag; tagged race
passed after the test-helper fix. Linux amd64 Docker Desktop tests observed
real GRO, without skips, in IPv4 and IPv6:64000-byte/64-segment aggregates,
63888-byte/44-segment full-MTU aggregates, and a2935-byte short-tail aggregate.
The socket staging retained65535-byte slots while split destinations were2016.
Real UDP send passed with GSO enabled and with it disabled.

The smaller capacity loses full-MTU TX coalescing:8*1452 produces8 messages,
while8*128 still produces1. The tests validate transit and disabled-offload
fallback, not a forced NIC EIO recovery, CPU cost or throughput. Linux race was
not run because the available local image has no C compiler; race evidence is
native Darwin. Windows device/conn cross-compilation passed (not execution).

Tests include red/green retention across all five pools, nil/factory behavior,
positive-max behavior, concurrent lease ownership, staging eviction, cookie
pressure, MTU1420 IPv4/IPv6 with PSK, malformed/truncated/replayed inputs, and
progress/close while the receiver TUN is blocked. See the external worker report
and local ignored evidence logs for exact commands and outcomes.

## Temporary consumption, not publication

Keep the replacement modfile outside the consumer checkout. The coordinator
or peer owner can run the following from this clone, setting R2_CONSUMER_ROOT
to the consumer worktree containing the oversize fix. These commands are not
executed by this worker and change no consumer go.mod/go.sum.

```sh
r2_consumer_root=${R2_CONSUMER_ROOT:-/Users/adri4n/orca/workspaces/x-sys/r2-wg-bounds-options}
r2_profile_root=/tmp/r2-wg-resource-profile
mkdir -p "$r2_profile_root/evidence"
cp "$r2_consumer_root/go.mod" "$r2_profile_root/evidence/consumer.mod"
cp "$r2_consumer_root/go.sum" "$r2_profile_root/evidence/consumer.sum"
GOWORK=off go -C "$r2_consumer_root" mod edit -modfile="$r2_profile_root/evidence/consumer.mod" -replace=golang.zx2c4.com/wireguard="$r2_profile_root"
GOWORK=off go -C "$r2_consumer_root" test -modfile="$r2_profile_root/evidence/consumer.mod" -tags=r2resourceprofile ./agent/internal/peer -run 'TestWGCompactBind|TestWGIngress|TestWGCompactGROFullDatagram' -count=1
```

For Linux GRO also set WG_GRO_TEST=1 on a supported local runner. The existing
F5 fixture and CPU/RSS comparison remain with their owner; do not equate the
above smoke with that evaluation.

After evaluation, a published dependency would need an immutable reviewed
commit/version, upstream SHA and MIT provenance. To avoid final consumer
build-flag changes, a separate promotion should make this dedicated fork's
profile default on the approved Linux/Darwin targets, preserving other target
defaults; that is not part of this prototype. The coordinator chooses the remote,
module/replacement/version policy and publication. No remote fork/tag/push was
created here. This clone keeps the upstream module path for local replacement.
