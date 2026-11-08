/* SPDX-License-Identifier: MIT */

package device

import (
	"context"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"golang.zx2c4.com/wireguard/conn/bindtest"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

func TestCryptoExecutorAdmission(t *testing.T) {
	for _, workers := range []int{-1, 0, runtime.GOMAXPROCS(0) + 1} {
		if exec, err := NewCryptoExecutor(workers); err == nil {
			exec.Close(context.Background())
			t.Fatalf("accepted invalid workers %d", workers)
		}
	}
	if _, err := NewDeviceWithCryptoExecutor(nil, nil, nil, new(CryptoExecutor)); err == nil {
		t.Fatal("accepted zero executor")
	}
	if err := new(CryptoExecutor).Close(context.Background()); err == nil {
		t.Fatal("closed zero executor without error")
	}
	if _, err := NewDeviceWithCryptoExecutor(nil, nil, nil, nil); err == nil {
		t.Fatal("accepted nil executor")
	}
	exec, err := NewCryptoExecutor(1)
	if err != nil {
		t.Fatal(err)
	}
	if err := exec.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDeviceWithCryptoExecutor(nil, nil, nil, exec); err == nil {
		t.Fatal("accepted closed executor")
	}
	if err := exec.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func newCryptoTestDevices(t *testing.T, workers int) (*CryptoExecutor, [2]*Device) {
	return newCryptoTestDevicesWithPolicy(t, workers, nil)
}

func newCryptoTestDevicesWithPolicy(t *testing.T, workers int, policy *ServicePolicy) (*CryptoExecutor, [2]*Device) {
	t.Helper()
	var exec *CryptoExecutor
	var err error
	if policy == nil {
		exec, err = NewCryptoExecutor(workers)
	} else {
		exec, err = NewCryptoExecutorWithServicePolicy(workers, policy)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := exec.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	binds := bindtest.NewChannelBinds()
	var devices [2]*Device
	for i := range devices {
		devices[i], err = NewDeviceWithCryptoExecutor(tuntest.NewChannelTUN().TUN(), binds[i], NewLogger(LogLevelSilent, ""), exec)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(devices[i].Close)
	}
	return exec, devices
}

// The gate wraps the existing AEAD interface; production has no test hook.
type cryptoActivity struct {
	current atomic.Int32
	maximum atomic.Int32
}

type cryptoGate struct {
	activity *cryptoActivity
	cipher.AEAD
	lane    int
	entered chan<- int
	release <-chan struct{}
}

func (g *cryptoGate) Seal(dst, nonce, plaintext, additional []byte) []byte {
	g.enter(nonce)
	defer g.activity.current.Add(-1)
	return g.AEAD.Seal(dst, nonce, plaintext, additional)
}

func (g *cryptoGate) Open(dst, nonce, ciphertext, additional []byte) ([]byte, error) {
	g.enter(nonce)
	defer g.activity.current.Add(-1)
	return g.AEAD.Open(dst, nonce, ciphertext, additional)
}

func cryptoEvent(t *testing.T, events <-chan int, want int) {
	t.Helper()
	select {
	case got := <-events:
		if got != want {
			t.Fatalf("crypto grant = %d, want %d", got, want)
		}
	case <-time.After(time.Second):
		t.Fatalf("no crypto grant for lane %d", want)
	}
}

func TestCryptoExecutorCloseTimeout(t *testing.T) {
	exec, devices := newCryptoTestDevices(t, 1)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if err := exec.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("close before devices = %v", err)
	}
	if _, err := NewDeviceWithCryptoExecutor(nil, nil, nil, exec); err == nil {
		t.Fatal("accepted registration after timed out close")
	}
	devices[0].Close()
	devices[1].Close()
	if err := exec.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func (g *cryptoGate) enter(nonce []byte) {
	current := g.activity.current.Add(1)
	for old := g.activity.maximum.Load(); current > old; old = g.activity.maximum.Load() {
		if g.activity.maximum.CompareAndSwap(old, current) {
			break
		}
	}
	g.entered <- g.lane*100 + int(binary.LittleEndian.Uint64(nonce[4:]))
	<-g.release
}

func cryptoCipher(t *testing.T) cipher.AEAD {
	t.Helper()
	aead, err := chacha20poly1305.New(make([]byte, chacha20poly1305.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return aead
}

// Queue fixtures use real AEAD and the existing completion mutex. Destructive
// reuse immediately after completion makes any post-Unlock access race-visible.
func cryptoQueueTX(t *testing.T, device *Device, aead cipher.AEAD, counter uint64) func() {
	t.Helper()
	buffer := new([MaxMessageSize]byte)
	buffer[MessageTransportHeaderSize] = byte(counter)
	elem := &QueueOutboundElement{buffer: buffer, packet: buffer[MessageTransportHeaderSize : MessageTransportHeaderSize+1], nonce: counter, keypair: &Keypair{send: aead}}
	container := &QueueOutboundElementsContainer{elems: []*QueueOutboundElement{elem}}
	container.Lock()
	device.enqueueEncryption(container)
	return func() {
		container.Lock()
		if got := binary.LittleEndian.Uint64(elem.packet[8:16]); got != counter {
			t.Errorf("TX nonce = %d, want %d", got, counter)
		}
		container.elems = nil
		elem.clearPointers()
		container.Unlock()
	}
}

func cryptoQueueRX(t *testing.T, device *Device, aead cipher.AEAD, counter uint64) func() {
	t.Helper()
	buffer := new([MaxMessageSize]byte)
	binary.LittleEndian.PutUint64(buffer[8:16], counter)
	var nonce [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	// Build valid input without entering the gate used by the crypto worker.
	plainAEAD := aead
	if gate, ok := aead.(*cryptoGate); ok {
		plainAEAD = gate.AEAD
	}
	packet := plainAEAD.Seal(buffer[:MessageTransportHeaderSize], nonce[:], []byte{byte(counter)}, nil)
	elem := &QueueInboundElement{buffer: buffer, packet: packet, keypair: &Keypair{receive: aead}}
	container := &QueueInboundElementsContainer{elems: []*QueueInboundElement{elem}}
	container.Lock()
	device.enqueueDecryption(container)
	return func() {
		container.Lock()
		if elem.counter != counter || len(elem.packet) != 1 || elem.packet[0] != byte(counter) {
			t.Errorf("RX payload/counter mismatch for %d", counter)
		}
		container.elems = nil
		elem.clearPointers()
		container.Unlock()
	}
}

func TestCryptoExecutorRoundRobin(t *testing.T) {
	testCryptoExecutorRoundRobin(t, nil)
}

func TestServiceFloorRoundRobin(t *testing.T) {
	policy, err := NewServicePolicy(10*time.Millisecond, 5*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(policy.Close)
	testCryptoExecutorRoundRobin(t, policy)
}

func testCryptoExecutorRoundRobin(t *testing.T, policy *ServicePolicy) {
	t.Helper()
	goroutineLeakCheck(t)
	exec, devices := newCryptoTestDevicesWithPolicy(t, 1, policy)
	entered := make(chan int, 16)
	release := make(chan struct{})
	activity := new(cryptoActivity)
	t.Cleanup(func() { close(release) })
	gates := [4]*cryptoGate{}
	for lane := range gates {
		gates[lane] = &cryptoGate{AEAD: cryptoCipher(t), lane: lane, entered: entered, release: release, activity: activity}
	}
	completed := []func(){cryptoQueueTX(t, devices[0], gates[0], 1)}
	cryptoEvent(t, entered, 1)
	// Keep all four lanes backlogged before releasing the first batch.
	completed = append(completed, cryptoQueueTX(t, devices[0], gates[0], 2))
	for counter := uint64(1); counter <= 2; counter++ {
		completed = append(completed, cryptoQueueRX(t, devices[0], gates[1], counter), cryptoQueueTX(t, devices[1], gates[2], counter), cryptoQueueRX(t, devices[1], gates[3], counter))
	}
	// Device round-robin, alternating TX/RX within each device, with FIFO counters.
	for _, want := range []int{201, 101, 301, 2, 202, 102, 302} {
		release <- struct{}{}
		cryptoEvent(t, entered, want)
	}
	release <- struct{}{}
	for _, complete := range completed {
		complete()
	}
	if got := activity.maximum.Load(); got != 1 {
		t.Fatalf("simultaneous AEAD calls = %d, want W=1", got)
	}
	devices[0].Close()
	// A detached device must not stop its still registered neighbour.
	cryptoQueueTX(t, devices[1], cryptoCipher(t), 3)()
	// A timed-out pool close seals admission but must still execute both directions.
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if err := exec.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	cryptoQueueTX(t, devices[1], cryptoCipher(t), 4)()
	cryptoQueueRX(t, devices[1], cryptoCipher(t), 5)()
}

func TestCryptoExecutorParallelLanes(t *testing.T) {
	if runtime.GOMAXPROCS(0) < 2 {
		t.Skip("requires GOMAXPROCS >= 2")
	}
	_, devices := newCryptoTestDevices(t, 2)
	entered := make(chan int, 16)
	releases := [2]chan struct{}{make(chan struct{}), make(chan struct{})}
	activity := new(cryptoActivity)
	t.Cleanup(func() {
		for _, release := range releases {
			close(release)
		}
	})
	aead := cryptoCipher(t)
	gates := [3]*cryptoGate{
		{AEAD: aead, lane: 0, entered: entered, release: releases[0], activity: activity},
		{AEAD: aead, lane: 1, entered: entered, release: releases[1], activity: activity},
		{AEAD: aead, lane: 2, entered: entered, release: releases[1], activity: activity},
	}
	first := cryptoQueueTX(t, devices[0], gates[0], 1)
	cryptoEvent(t, entered, 1)
	sameLane := cryptoQueueTX(t, devices[0], gates[0], 2)
	otherDevice := cryptoQueueTX(t, devices[1], gates[2], 1)
	cryptoEvent(t, entered, 201) // second worker skips the already-active lane
	otherDirection := cryptoQueueRX(t, devices[0], gates[1], 1)
	releases[1] <- struct{}{}
	cryptoEvent(t, entered, 101)
	releases[1] <- struct{}{}
	otherDevice()
	otherDirection()
	releases[0] <- struct{}{}
	cryptoEvent(t, entered, 2)
	releases[0] <- struct{}{}
	first()
	sameLane()
	if got := activity.maximum.Load(); got != 2 {
		t.Fatalf("simultaneous AEAD calls = %d, want W=2", got)
	}
}

func TestCryptoExecutorStopDrainsPendingBatch(t *testing.T) {
	testCryptoExecutorStopDrainsPendingBatch(t, nil)
}

func TestServiceFloorStopDrainsPendingBatch(t *testing.T) {
	policy, err := NewServicePolicy(10*time.Millisecond, 5*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(policy.Close)
	testCryptoExecutorStopDrainsPendingBatch(t, policy)
}

func testCryptoExecutorStopDrainsPendingBatch(t *testing.T, policy *ServicePolicy) {
	t.Helper()
	goroutineLeakCheck(t)
	var exec *CryptoExecutor
	var err error
	if policy == nil {
		exec, err = NewCryptoExecutor(1)
	} else {
		exec, err = NewCryptoExecutorWithServicePolicy(1, policy)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := exec.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	stopping := make(chan struct{})
	var once sync.Once
	logger := &Logger{Errorf: DiscardLogf, Verbosef: func(format string, args ...any) {
		if format == "%v - Stopping" {
			once.Do(func() { close(stopping) })
		}
	}}
	binds := bindtest.NewChannelBinds()
	device, err := NewDeviceWithCryptoExecutor(tuntest.NewChannelTUN().TUN(), binds[0], logger, exec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(device.Close)
	if err := device.Up(); err != nil {
		t.Fatal(err)
	}
	peer, err := device.NewPeer(NoisePublicKey{9})
	if err != nil {
		t.Fatal(err)
	}
	peer.Start()
	entered := make(chan int, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	gate := &cryptoGate{AEAD: cryptoCipher(t), entered: entered, release: release, activity: new(cryptoActivity)}
	// Preserve real pooled ownership and the sequential sender's completion wait.
	container := device.GetOutboundElementsContainer()
	elem := device.NewOutboundElement()
	elem.packet = elem.buffer[MessageTransportHeaderSize : MessageTransportHeaderSize+1]
	elem.keypair = &Keypair{send: gate}
	elem.peer = peer
	container.elems = append(container.elems, elem)
	container.Lock()
	peer.queue.outbound.c <- container
	device.enqueueEncryption(container)
	cryptoEvent(t, entered, 0)
	stopped := make(chan struct{})
	go func() { peer.Stop(); close(stopped) }()
	select {
	case <-stopping: // existing logger observes isRunning=false before Stop's drain
	case <-time.After(time.Second):
		t.Fatal("Stop did not start")
	}
	if peer.isRunning.Load() {
		t.Fatal("peer still running after Stop transition")
	}
	select {
	case <-stopped:
		t.Fatal("Stop returned before the pending crypto completion")
	default:
	}
	unblock()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("Stop did not drain after crypto completion")
	}
	device.pool.outboundElements.lock.Lock()
	outstanding := device.pool.outboundElements.count
	device.pool.outboundElements.lock.Unlock()
	if outstanding != 0 {
		t.Errorf("outbound elements still outstanding: %d", outstanding)
	}
}

func TestCryptoExecutorCloseWaitsForDevices(t *testing.T) {
	exec, devices := newCryptoTestDevices(t, 1)
	result := make(chan error, 1)
	exec.mu.Lock()
	go func() { result <- exec.Close(context.Background()) }()
	for !exec.closing {
		exec.cond.Wait()
	}
	exec.mu.Unlock()
	select {
	case err := <-result:
		t.Fatalf("pool closed with devices alive: %v", err)
	default:
	}
	devices[0].Close()
	cryptoQueueTX(t, devices[1], cryptoCipher(t), 1)()
	cryptoQueueRX(t, devices[1], cryptoCipher(t), 2)()
	devices[1].Close()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("pool close did not join workers")
	}
}

type cryptoInitTUN struct {
	tun.Device
	entered chan struct{}
	release chan struct{}
}

func (t *cryptoInitTUN) MTU() (int, error) {
	close(t.entered)
	<-t.release
	return t.Device.MTU()
}

func TestCryptoExecutorCloseDuringInitialization(t *testing.T) {
	exec, err := NewCryptoExecutor(1)
	if err != nil {
		t.Fatal(err)
	}
	binds := bindtest.NewChannelBinds()
	input := &cryptoInitTUN{Device: tuntest.NewChannelTUN().TUN(), entered: make(chan struct{}), release: make(chan struct{})}
	result := make(chan *Device, 1)
	errorsSeen := make(chan error, 1)
	go func() {
		device, err := NewDeviceWithCryptoExecutor(input, binds[0], NewLogger(LogLevelSilent, ""), exec)
		errorsSeen <- err
		result <- device
	}()
	select {
	case <-input.entered:
	case <-time.After(time.Second):
		t.Fatal("constructor did not reach initialization")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := exec.Close(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("close during accepted initialization = %v", err)
	}
	close(input.release)
	if err := <-errorsSeen; err != nil {
		t.Fatal(err)
	}
	device := <-result
	cryptoQueueTX(t, device, cryptoCipher(t), 1)()
	device.Close()
	if err := exec.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}
