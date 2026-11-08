//go:build r2resourceprofile || (linux && !android) || (darwin && !ios)

/* SPDX-License-Identifier: MIT */

package device

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func cryptoTestExecutor(t *testing.T) *CryptoExecutor {
	t.Helper()
	exec, err := NewCryptoExecutor(1)
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
	return exec
}

func TestCryptoExecutorTransport(t *testing.T) {
	goroutineLeakCheck(t)
	for _, mode := range []string{"shared", "shared_legacy", "legacy_shared", "floor", "floor_legacy", "legacy_floor"} {
		t.Run(mode, func(t *testing.T) {
			var exec *CryptoExecutor
			if strings.Contains(mode, "floor") {
				exec = serviceTestExecutor(t)
			} else {
				exec = cryptoTestExecutor(t)
			}
			executors := [2]*CryptoExecutor{exec, exec}
			if mode == "shared_legacy" || mode == "floor_legacy" {
				executors[1] = nil
			}
			if mode == "legacy_shared" || mode == "legacy_floor" {
				executors[0] = nil
			}
			p := newR2FlowPairWithExecutors(t, executors)
			// Actual Noise handshake and PSK, IPv4/IPv6, MTU1420, batching and FIFO.
			for _, ipv6 := range []bool{false, true} {
				for from := range p.dev {
					packets := make([][]byte, 8)
					for i := range packets {
						packets[i] = r2IPPacket(ipv6, byte(from+1), byte(2-from), byte(i+1))
						p.send(t, from, packets[i])
					}
					for i, want := range packets {
						select {
						case got := <-p.tun[from^1].rx:
							if !bytes.Equal(got, want) {
								t.Fatalf("FIFO/payload mismatch from %d packet %d ipv6=%v", from, i, ipv6)
							}
						case <-time.After(time.Second):
							t.Fatalf("transport stalled from %d packet %d ipv6=%v", from, i, ipv6)
						}
					}
				}
			}
			// Replaying a completed transport or truncating its tag must not deliver IP
			// or prevent a fresh packet from passing the unchanged receiver checks.
			wire := p.bind[0].last.Load().([]byte)
			p.bind[1].rx[0] <- [][]byte{bytes.Clone(wire), bytes.Clone(wire[:len(wire)-1])}
			marker := r2IPPacket(false, 1, 2, 255)
			p.send(t, 0, marker)
			select {
			case got := <-p.tun[1].rx:
				if !bytes.Equal(got, marker) {
					t.Fatal("replayed or unauthenticated packet delivered")
				}
			case <-time.After(time.Second):
				t.Fatal("fresh packet did not progress after replay/malformed input")
			}
		})
	}
}

func TestCryptoExecutorBlockedTUNClose(t *testing.T) {
	for _, closeBlocked := range []bool{false, true} {
		t.Run(fmt.Sprintf("close_blocked_%v", closeBlocked), func(t *testing.T) {
			exec := cryptoTestExecutor(t)
			p := newR2FlowPairWithExecutors(t, [2]*CryptoExecutor{exec, exec})
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
			if closeBlocked {
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

func serviceTestExecutor(t *testing.T) *CryptoExecutor {
	t.Helper()
	policy, err := NewServicePolicy(10*time.Millisecond, 5*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(policy.Close)
	exec, err := NewCryptoExecutorWithServicePolicy(1, policy)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := exec.Close(ctx); err != nil {
			t.Error(err)
		}
		if snapshot := policy.Snapshot(); snapshot.Waiters != 0 || snapshot.TimerActive {
			t.Error("device/executor shutdown left policy activity")
		}
	})
	return exec
}

func TestServiceFloorBlockedTUNClose(t *testing.T) {
	exec := serviceTestExecutor(t)
	p := newR2FlowPairWithExecutors(t, [2]*CryptoExecutor{exec, exec})
	warm := r2IPPacket(false, 1, 2, 1)
	p.send(t, 0, warm)
	p.receive(t, 1, warm)
	gate := &r2WriteGate{entered: make(chan struct{}), release: make(chan struct{})}
	p.tun[1].gate.Store(gate)
	for i := range 64 {
		p.send(t, 0, r2IPPacket(false, 1, 2, byte(i+2)))
	}
	select {
	case <-gate.entered:
	case <-time.After(time.Second):
		t.Fatal("blocked Write not entered")
	}
	p.close(t)
}

func TestServiceFloorInvalidAEADAndNoise(t *testing.T) {
	exec := serviceTestExecutor(t)
	p := newR2FlowPairWithExecutors(t, [2]*CryptoExecutor{exec, exec})
	warm := r2IPPacket(false, 1, 2, 1)
	p.send(t, 0, warm)
	p.receive(t, 1, warm)
	wire := p.bind[0].last.Load().([]byte)
	for range 8 {
		batch := make([][]byte, 8)
		for i := range batch {
			if i%2 == 0 {
				batch[i] = bytes.Clone(wire)
				batch[i][len(batch[i])-1] ^= 1 // valid index, invalid tag
			} else {
				batch[i] = make([]byte, MessageInitiationSize)
				batch[i][0] = MessageInitiationType // invalid Noise/MAC
			}
		}
		p.bind[1].rx[0] <- batch
	}
	marker := r2IPPacket(false, 1, 2, 255)
	p.send(t, 0, marker)
	p.receive(t, 1, marker)
	select {
	case <-p.tun[1].rx:
		t.Fatal("invalid flood delivered an IP packet")
	default:
	}
}
