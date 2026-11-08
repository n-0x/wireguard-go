//go:build go1.25

/* SPDX-License-Identifier: MIT */

package device

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"
)

func TestServicePolicyValidation(t *testing.T) {
	for _, tc := range []struct {
		name         string
		period, data time.Duration
	}{
		{"zero", 0, 0}, {"negative", -1, 1},
		{"no_data", time.Millisecond, 0},
		{"no_control", time.Millisecond, time.Millisecond},
		{"too_much_data", time.Millisecond, 2 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewServicePolicy(tc.period, tc.data); err == nil {
				t.Fatal("invalid service split accepted")
			}
		})
	}
	if err := new(ServicePolicy).Wait(context.Background()); err == nil {
		t.Fatal("zero policy accepted")
	}
}

func TestServicePolicyPhasesAndCoalescing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, err := NewServicePolicy(10*time.Millisecond, 5*time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		if err := p.Wait(context.Background()); err != nil {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Millisecond)
		done := make(chan error, 2)
		for range 2 {
			go func() { done <- p.Wait(context.Background()) }()
		}
		synctest.Wait()
		p.mu.Lock()
		if p.waiters != 2 || p.timer == nil {
			t.Fatal("waiters did not share a timer")
		}
		timer := p.timer
		p.mu.Unlock()
		select {
		case <-done:
			t.Fatal("control turn admitted data")
		default:
		}
		time.Sleep(4 * time.Millisecond)
		synctest.Wait()
		p.mu.Lock()
		if p.timer != timer {
			t.Fatal("timer was reset by another waiter")
		}
		p.mu.Unlock()
		time.Sleep(time.Millisecond)
		synctest.Wait()
		for range 2 {
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.waiters != 0 || p.timer != nil {
			t.Fatal("idle policy retained timer/waiters")
		}
	})
}

func TestServicePolicyCancelAndClose(t *testing.T) {
	for _, closePolicy := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "close"}[closePolicy], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p, err := NewServicePolicy(10*time.Millisecond, 5*time.Millisecond)
				if err != nil {
					t.Fatal(err)
				}
				defer p.Close()
				time.Sleep(6 * time.Millisecond)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				done := make(chan error, 1)
				go func() { done <- p.Wait(ctx) }()
				synctest.Wait()
				if closePolicy {
					p.Close()
				} else {
					cancel()
				}
				synctest.Wait()
				want := context.Canceled
				if closePolicy {
					want = ErrServicePolicyClosed
				}
				if err := <-done; !errors.Is(err, want) {
					t.Fatalf("Wait=%v, want %v", err, want)
				}
				p.mu.Lock()
				if p.timer != nil || p.waiters != 0 {
					t.Fatal("cancel/close leaked active timer")
				}
				p.mu.Unlock()
			})
		})
	}
}

func TestServicePolicyExecutorEpochDoesNotResetPhase(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, err := NewServicePolicy(10*time.Millisecond, 5*time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		epoch := p.epoch
		e, err := NewCryptoExecutorWithServicePolicy(1, p)
		if err != nil {
			t.Fatal(err)
		}
		if err := e.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		time.Sleep(6 * time.Millisecond)
		e, err = NewCryptoExecutorWithServicePolicy(1, p)
		if err != nil {
			t.Fatal(err)
		}
		defer e.Close(context.Background())
		if p.epoch != epoch {
			t.Fatal("new executor reset process epoch")
		}
		done := make(chan error, 1)
		go func() { done <- p.Wait(context.Background()) }()
		synctest.Wait()
		select {
		case <-done:
			t.Fatal("new epoch got early data quota")
		default:
		}
		time.Sleep(4 * time.Millisecond)
		synctest.Wait()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	})
}

func TestServicePolicyClosingDeviceDrainsWithoutEarlyQuotaForNeighbour(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, err := NewServicePolicy(10*time.Millisecond, 5*time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		_, devices := newCryptoTestDevicesWithPolicy(t, 1, p)
		time.Sleep(6 * time.Millisecond)
		completeFirst := cryptoQueueTX(t, devices[0], cryptoCipher(t), 1)
		synctest.Wait() // accepted batch waits for policy outside executor.mu
		entered, release := make(chan int, 1), make(chan struct{})
		defer func() {
			select {
			case <-release:
			default:
				close(release)
			}
		}()
		secondCipher := &cryptoGate{AEAD: cryptoCipher(t), entered: entered, release: release, activity: new(cryptoActivity)}
		completeSecond := cryptoQueueTX(t, devices[1], secondCipher, 2)
		closed := make(chan struct{})
		go func() { devices[0].Close(); close(closed) }()
		synctest.Wait()
		select {
		case <-closed:
		default:
			t.Fatal("Close did not wake accepted crypto to drain")
		}
		completeFirst()
		if !time.Now().Before(p.epoch.Add(10 * time.Millisecond)) {
			t.Fatal("closing device waited for a future data turn")
		}
		select {
		case <-entered:
			t.Fatal("closing one device granted early neighbour quota")
		default:
		}
		time.Sleep(4 * time.Millisecond)
		synctest.Wait()
		select {
		case <-entered:
		default:
			t.Fatal("neighbour did not receive its mandatory data opportunity")
		}
		close(release)
		synctest.Wait()
		completeSecond()
		devices[1].Close()
	})
}

func TestServicePolicyOneCanceledWaiterRetainsSharedWake(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, err := NewServicePolicy(10*time.Millisecond, 5*time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		time.Sleep(6 * time.Millisecond)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		canceled, ready := make(chan error, 1), make(chan error, 1)
		go func() { canceled <- p.Wait(ctx) }()
		go func() { ready <- p.Wait(context.Background()) }()
		synctest.Wait()
		cancel()
		synctest.Wait()
		if err := <-canceled; !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		s := p.Snapshot()
		if s.Waiters != 1 || !s.TimerActive {
			t.Fatal("cancel removed a shared wake needed by another waiter")
		}
		select {
		case <-ready:
			t.Fatal("cancellation granted early data quota")
		default:
		}
		time.Sleep(4 * time.Millisecond)
		synctest.Wait()
		if err := <-ready; err != nil {
			t.Fatal(err)
		}
	})
}
