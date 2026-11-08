# Shared transport crypto (opt-in)

`NewDevice` retains its existing per-device encryption/decryption workers and
constructor signature. `NewDeviceWithCryptoExecutor` opts devices into one
caller-owned executor shared by transport encryption **and** decryption:

```go
executor, err := device.NewCryptoExecutor(workers)
if err != nil {
    return err
}
wg, err := device.NewDeviceWithCryptoExecutor(tunDevice, bind, logger, executor)
```

Declare `workers` by capacity before construction, in `[1, runtime.GOMAXPROCS(0)]`.
The caller can impose a smaller policy cap (for example, four); this package does
not create a singleton or choose workers from performance results. The worker
count is fixed for the lifetime of the executor, even if GOMAXPROCS later changes.

On constructor rejection, no device routines start and the caller still owns
TUN and bind. An accepted registration is reserved before initialization, so an
executor close racing that initialization waits for that device too. Do not copy
an executor or use its zero value.

Close every accepted device first, retaining the caller's executor reference
until `Device.Close` returns. `executor.Close(ctx)` seals new admissions and joins
workers after all devices have detached. Calling it earlier is allowed but waits
for those devices. A context error ends only that caller's wait: workers keep
serving and draining accepted devices, and `Close` can be retried. `Device.Close`
never closes the executor. No caller may enqueue work after its device closes.

The scheduler rotates across devices and alternates TX/RX within each device.
Each grant processes one existing container; at most one batch is active per
device/direction. An idle or busy lane is skipped. Empty queues use `sync.Cond`,
and producer completion notifies the executor after closing each crypto channel.
There is no polling timer, per-device watcher, or additional payload queue.
Detach follows peer shutdown and producer drain, then waits for both queue EOFs
and active completions. Crypto publishes the existing completion mutex unlock
as its last container access; the sequential sender/receiver retains buffer
ownership, FIFO, replay checking, and terminal disposal.

This is fairness of batch grants, not equal CPU time or bytes. Scanning costs
O(devices) per grant; registration/scratch state costs O(devices + workers).
Overlapping generations remain separate devices and receive separate turns.
Existing R2 batch size eight, queue capacities eight, and pool policy are
unchanged. Slots are released at dequeue/helper completion, not at Send/Write.
This does not bound aggregate packet WIP, total CPU, TUN or Send work, latency,
or throughput, and makes no SLO or performance claim. Handshake, probes, Noise,
PSK, transport wire format, keypair/nonce/padding rules, replay, bind, and network
locks keep their existing paths; there is no new probe bypass.

Focused tests cover deterministic W1 device/direction grants, W2 parallelism and
lane exclusion, completion reuse, initialization/close races, timeout followed
by progress, one-device close with its neighbour alive, pending peer Stop,
PSK/IPv4/IPv6/MTU1420/batch-eight FIFO, mixed legacy/shared interoperability,
replay/malformed rejection, and blocked TUN shutdown. Go 1.25+ additionally runs
a `testing/synctest` check that empty EOF wakes durably sleeping workers; older
supported toolchains omit only that test. No production test hooks are added.
