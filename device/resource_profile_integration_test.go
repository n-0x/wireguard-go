//go:build r2resourceprofile || (linux && !android) || (darwin && !ios)

/* SPDX-License-Identifier: MIT */

package device

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/conn/bindtest"
	"golang.zx2c4.com/wireguard/tun"
)

type r2WriteGate struct {
	entered, release chan struct{}
	once             sync.Once
}
type r2FlowTUN struct {
	tx, rx chan []byte
	done   chan struct{}
	events chan tun.Event
	once   sync.Once
	gate   atomic.Pointer[r2WriteGate]
}

func newR2FlowTUN() *r2FlowTUN {
	return &r2FlowTUN{tx: make(chan []byte, 512), rx: make(chan []byte, 512), done: make(chan struct{}), events: make(chan tun.Event)}
}
func (t *r2FlowTUN) File() *os.File           { return nil }
func (t *r2FlowTUN) MTU() (int, error)        { return 1420, nil }
func (t *r2FlowTUN) Name() (string, error)    { return "r2-profile-test", nil }
func (t *r2FlowTUN) Events() <-chan tun.Event { return t.events }
func (t *r2FlowTUN) BatchSize() int           { return 8 }
func (t *r2FlowTUN) Close() error             { t.once.Do(func() { close(t.done); close(t.events) }); return nil }
func (t *r2FlowTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	var raw []byte
	select {
	case <-t.done:
		return 0, os.ErrClosed
	case raw = <-t.tx:
	}
	n := 0
	for {
		if len(raw) > len(bufs[n])-offset {
			return n, fmt.Errorf("test packet exceeds buffer")
		}
		sizes[n] = copy(bufs[n][offset:], raw)
		n++
		if n == len(bufs) {
			return n, nil
		}
		select {
		case raw = <-t.tx:
		default:
			return n, nil
		}
	}
}
func (t *r2FlowTUN) Write(bufs [][]byte, offset int) (int, error) {
	if g := t.gate.Load(); g != nil {
		g.once.Do(func() { close(g.entered) })
		select {
		case <-g.release:
		case <-t.done:
			return 0, os.ErrClosed
		}
	}
	for i, buf := range bufs {
		raw := bytes.Clone(buf[offset:])
		select {
		case <-t.done:
			return i, os.ErrClosed
		case t.rx <- raw:
		}
	}
	return len(bufs), nil
}

type r2WireBind struct {
	id    uint16
	rx    [2]chan [][]byte
	other *r2WireBind
	done  chan struct{}
	mu    sync.Mutex
	last  atomic.Value
}

func newR2WireBinds() [2]*r2WireBind {
	var pair [2]*r2WireBind
	for i := range pair {
		pair[i] = &r2WireBind{id: uint16(i + 1), rx: [2]chan [][]byte{make(chan [][]byte, 8), make(chan [][]byte, 8)}}
	}
	pair[0].other, pair[1].other = pair[1], pair[0]
	return pair
}
func (b *r2WireBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	b.done = make(chan struct{})
	done := b.done
	b.mu.Unlock()
	fns := make([]conn.ReceiveFunc, 2)
	for i := range fns {
		q := b.rx[i]
		fns[i] = func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			select {
			case <-done:
				return 0, net.ErrClosed
			case batch := <-q:
				for j, raw := range batch {
					sizes[j] = copy(bufs[j], raw)
					eps[j] = bindtest.ChannelEndpoint(b.other.id)
				}
				return len(batch), nil
			}
		}
	}
	return fns, b.id, nil
}
func (b *r2WireBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.done != nil {
		select {
		case <-b.done:
		default:
			close(b.done)
		}
	}
	return nil
}
func (b *r2WireBind) BatchSize() int       { return 8 }
func (b *r2WireBind) SetMark(uint32) error { return nil }
func (b *r2WireBind) ParseEndpoint(raw string) (conn.Endpoint, error) {
	a, e := netip.ParseAddrPort(raw)
	return bindtest.ChannelEndpoint(a.Port()), e
}
func (b *r2WireBind) Send(bufs [][]byte, _ conn.Endpoint) error {
	batch := make([][]byte, len(bufs))
	for i, raw := range bufs {
		batch[i] = bytes.Clone(raw)
		if len(raw) > 32 && binary.LittleEndian.Uint32(raw[:4]) == 4 {
			b.last.Store(bytes.Clone(raw))
		}
	}
	b.mu.Lock()
	done := b.done
	b.mu.Unlock()
	b.other.mu.Lock()
	otherDone := b.other.done
	b.other.mu.Unlock()
	select {
	case <-done:
		return net.ErrClosed
	case <-otherDone:
		return net.ErrClosed
	case b.other.rx[0] <- batch:
		return nil
	}
}

type r2FlowPair struct {
	dev  [2]*Device
	tun  [2]*r2FlowTUN
	bind [2]*r2WireBind
}

func newR2FlowPair(t *testing.T) *r2FlowPair {
	return newR2FlowPairWithExecutors(t, [2]*CryptoExecutor{})
}

func newR2FlowPairWithExecutors(t *testing.T, executors [2]*CryptoExecutor) *r2FlowPair {
	t.Helper()
	p := &r2FlowPair{bind: newR2WireBinds()}
	cfg, endpoints := genConfigs(t)
	for i := range p.dev {
		p.tun[i] = newR2FlowTUN()
		level := LogLevelSilent
		if testing.Verbose() {
			level = LogLevelVerbose
		}
		logger := NewLogger(level, fmt.Sprintf("r2-dev%d: ", i))
		if executors[i] == nil {
			p.dev[i] = NewDevice(p.tun[i], p.bind[i], logger)
		} else {
			var err error
			p.dev[i], err = NewDeviceWithCryptoExecutor(p.tun[i], p.bind[i], logger, executors[i])
			if err != nil {
				t.Fatal(err)
			}
		}
		if e := p.dev[i].IpcSet(cfg[i] + "preshared_key=" + fmt.Sprintf("%064x", 1) + "\nallowed_ip=" + fmt.Sprintf("fd00::%d/128", 2-i) + "\n"); e != nil {
			t.Fatal(e)
		}
		if e := p.dev[i].Up(); e != nil {
			t.Fatal(e)
		}
	}
	for i := range p.dev {
		if e := p.dev[i].IpcSet(fmt.Sprintf(endpoints[i], p.bind[i^1].id)); e != nil {
			t.Fatal(e)
		}
	}
	t.Cleanup(func() { p.close(t) })
	return p
}
func (p *r2FlowPair) close(t *testing.T) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		for _, d := range p.dev {
			wg.Add(1)
			go func(d *Device) { defer wg.Done(); d.Close() }(d)
		}
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("devices failed to close with blocked traffic")
	}
}
func r2IPPacket(ipv6 bool, from, to byte, label byte) []byte {
	raw := make([]byte, 1420)
	if ipv6 {
		raw[0] = 0x60
		binary.BigEndian.PutUint16(raw[4:6], 1380)
		raw[6] = 59
		raw[7] = 64
		a := netip.MustParseAddr(fmt.Sprintf("fd00::%d", from)).As16()
		b := netip.MustParseAddr(fmt.Sprintf("fd00::%d", to)).As16()
		copy(raw[8:24], a[:])
		copy(raw[24:40], b[:])
	} else {
		raw[0] = 0x45
		binary.BigEndian.PutUint16(raw[2:4], 1420)
		raw[8] = 64
		raw[9] = 253
		copy(raw[12:16], []byte{1, 0, 0, from})
		copy(raw[16:20], []byte{1, 0, 0, to})
	}
	raw[len(raw)-1] = label
	return raw
}
func (p *r2FlowPair) send(t *testing.T, from int, raw []byte) {
	t.Helper()
	select {
	case p.tun[from].tx <- raw:
	case <-time.After(3 * time.Second):
		t.Fatal("TUN enqueue did not progress")
	}
}
func (p *r2FlowPair) receive(t *testing.T, to int, want []byte) {
	t.Helper()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for {
		select {
		case got := <-p.tun[to].rx:
			if bytes.Equal(got, want) {
				return
			}
		case <-timer.C:
			t.Fatal("expected MTU1420 packet did not transit")
		}
	}
}
func TestR2MTU1420WithPSK(t *testing.T) {
	p := newR2FlowPair(t)
	for _, ipv6 := range []bool{false, true} {
		for from := range 2 {
			raw := r2IPPacket(ipv6, byte(from+1), byte(2-from), byte(from+8))
			p.send(t, from, raw)
			p.receive(t, from^1, raw)
		}
	}
}
func TestR2SaturatedTrafficProgressAndClose(t *testing.T) {
	for _, closeWhileBlocked := range []bool{false, true} {
		t.Run(fmt.Sprintf("close_blocked_%v", closeWhileBlocked), func(t *testing.T) {
			p := newR2FlowPair(t)
			warm := r2IPPacket(false, 1, 2, 1)
			p.send(t, 0, warm)
			p.receive(t, 1, warm)
			gate := &r2WriteGate{entered: make(chan struct{}), release: make(chan struct{})}
			p.tun[1].gate.Store(gate)
			for i := range 256 {
				p.send(t, 0, r2IPPacket(false, 1, 2, byte(i%200+2)))
			}
			select {
			case <-gate.entered:
			case <-time.After(time.Second):
				t.Fatal("traffic did not reach blocked TUN")
			}
			if closeWhileBlocked {
				p.close(t)
				return
			}
			close(gate.release)
			marker := r2IPPacket(false, 1, 2, 255)
			p.send(t, 0, marker)
			p.receive(t, 1, marker)
		})
	}
}
func TestR2MalformedTruncatedAndReplayDoNotStopReceiver(t *testing.T) {
	p := newR2FlowPair(t)
	warm := r2IPPacket(false, 1, 2, 1)
	p.send(t, 0, warm)
	p.receive(t, 1, warm)
	wire := p.bind[0].last.Load().([]byte)
	variants := [][]byte{nil, {4}, {4, 0, 0, 0}, bytes.Clone(wire[:31]), bytes.Clone(wire[:len(wire)-1]), bytes.Clone(wire), make([]byte, 65535)}
	variants[6][0] = 4
	for _, raw := range variants {
		p.bind[1].rx[0] <- [][]byte{raw}
	}
	marker := r2IPPacket(true, 1, 2, 250)
	p.send(t, 0, marker)
	p.receive(t, 1, marker)
	select {
	case raw := <-p.tun[1].rx:
		t.Fatalf("malformed/replayed input delivered %d-byte packet", len(raw))
	default:
	}
}
