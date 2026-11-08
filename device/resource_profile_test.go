//go:build r2resourceprofile || (linux && !android) || (darwin && !ios)

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026. All Rights Reserved.
 */

package device

import (
	"runtime/debug"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun"
)

// Retention is an observable allocation contract: after returning 96 distinct
// objects, obtaining 96 again must create 64, even without a garbage collection.
func TestR2PoolRetainsOnly32(t *testing.T) {
	old := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(old)
	created := 0
	p := NewWaitPool(0, func() any { created++; return new(int) })
	held := make([]any, 96)
	for i := range held {
		held[i] = p.Get()
	}
	for _, x := range held {
		p.Put(x)
	}
	for i := range held {
		held[i] = p.Get()
	}
	if created != 160 {
		t.Fatalf("created %d objects; want 160 (96 initial + 64 cache misses)", created)
	}
	seen := make(map[any]bool)
	for _, x := range held {
		if seen[x] {
			t.Fatal("same object leased twice")
		}
		seen[x] = true
		p.Put(x)
	}
}

type r2BatchBind struct{ conn.Bind }

func (r2BatchBind) BatchSize() int { return 8 }

type r2BatchTUN struct{ tun.Device }

func (r2BatchTUN) BatchSize() int { return 8 }

func TestR2AllDevicePoolsBoundRetention(t *testing.T) {
	old := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(old)
	d := new(Device)
	d.net.bind = r2BatchBind{}
	d.tun.device = r2BatchTUN{}
	d.PopulatePools()
	cases := []struct {
		name string
		p    *WaitPool
	}{
		{"message buffers", d.pool.messageBuffers},
		{"inbound elements", d.pool.inboundElements},
		{"outbound elements", d.pool.outboundElements},
		{"inbound containers", d.pool.inboundElementsContainer},
		{"outbound containers", d.pool.outboundElementsContainer},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			original := make(map[any]bool)
			held := make([]any, 96)
			for i := range held {
				held[i] = tc.p.Get()
				original[held[i]] = true
			}
			for _, x := range held {
				tc.p.Put(x)
			}
			reused := 0
			for i := range held {
				held[i] = tc.p.Get()
				if original[held[i]] {
					reused++
				}
			}
			if reused != 32 {
				t.Fatalf("reused %d objects; want exactly 32 retained", reused)
			}
			for _, x := range held {
				tc.p.Put(x)
			}
		})
	}
}

func TestR2PoolExhaustedCacheDoesNotWait(t *testing.T) {
	done := make(chan struct{})
	p := NewWaitPool(0, func() any { return new(int) })
	go func() {
		held := make([]any, 256)
		for i := range held {
			held[i] = p.Get()
		}
		for _, x := range held {
			p.Put(x)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Get waited with 256 outstanding leases and max=0")
	}
}

func TestR2PoolConcurrentOwnership(t *testing.T) {
	type object struct{ leased atomic.Bool }
	p := NewWaitPool(0, func() any { return new(object) })
	var wg sync.WaitGroup
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 200 {
				x := p.Get().(*object)
				if !x.leased.CompareAndSwap(false, true) {
					t.Error("duplicate concurrent lease")
					return
				}
				x.leased.Store(false)
				p.Put(x)
			}
		}()
	}
	wg.Wait()
}

func TestR2WaitPoolPositiveMaxStillLimitsLeases(t *testing.T) {
	p := NewWaitPool(1, func() any { return new(int) })
	first := p.Get()
	entered, acquired := make(chan struct{}), make(chan any)
	go func() { close(entered); acquired <- p.Get() }()
	<-entered
	select {
	case <-acquired:
		t.Fatal("positive max allowed second outstanding lease")
	case <-time.After(10 * time.Millisecond):
	}
	p.Put(first)
	select {
	case next := <-acquired:
		p.Put(next)
	case <-time.After(time.Second):
		t.Fatal("Put did not wake blocked Get")
	}
}

func TestR2CookiePressureTracksSmallQueue(t *testing.T) {
	d := new(Device)
	d.queue.handshake = &handshakeQueue{c: make(chan QueueHandshakeElement, 8)}
	d.queue.handshake.c <- QueueHandshakeElement{}
	if !d.IsUnderLoad() {
		t.Fatal("one occupied slot in the eight-slot handshake queue did not enable cookie pressure")
	}
	<-d.queue.handshake.c
	if !d.IsUnderLoad() {
		t.Fatal("cookie load hysteresis was lost while draining")
	}
}

func TestR2StageDropsOldestBatch(t *testing.T) {
	d := new(Device)
	d.net.bind = r2BatchBind{}
	d.tun.device = r2BatchTUN{}
	d.peers.keyMap = make(map[NoisePublicKey]*Peer)
	d.PopulatePools()
	var sk NoisePrivateKey
	sk[0] = 1
	peer, err := d.NewPeer(sk.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer peer.FlushStagedPackets()
	for label := byte(1); label <= 3; label++ {
		c := d.GetOutboundElementsContainer()
		for range 8 {
			e := d.NewOutboundElement()
			e.packet = e.buffer[:1]
			e.packet[0] = label
			c.elems = append(c.elems, e)
		}
		peer.StagePackets(c)
	}
	if len(peer.queue.staged) != 2 {
		t.Fatalf("staged %d batches; want only the newest two", len(peer.queue.staged))
	}
	for _, want := range []byte{2, 3} {
		c := <-peer.queue.staged
		for _, e := range c.elems {
			if e.packet[0] != want {
				t.Errorf("batch label %d, want %d", e.packet[0], want)
			}
			d.PutMessageBuffer(e.buffer)
			d.PutOutboundElement(e)
		}
		d.PutOutboundElementsContainer(c)
	}
}

func TestR2PoolNilBehavior(t *testing.T) {
	t.Run("nil_put_does_not_replace_factory", func(t *testing.T) {
		p := NewWaitPool(0, func() any { return new(int) })
		p.Put(nil)
		x := p.Get()
		if x == nil {
			t.Fatal("Put(nil) hid an available factory, unlike sync.Pool")
		}
		p.Put(x)
	})
	t.Run("nil_factory_returns_nil", func(t *testing.T) {
		p := NewWaitPool(0, nil)
		if x := p.Get(); x != nil {
			t.Fatal("empty pool with nil factory returned an object")
		}
	})
}
