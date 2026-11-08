//go:build go1.25 && (r2resourceprofile || (linux && !android) || (darwin && !ios))

/* SPDX-License-Identifier: MIT */

package device

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"
)

func TestServiceFloorSendWaitCloseAndStop(t *testing.T) {
	for _, stopPeer := range []bool{false, true} {
		t.Run(map[bool]string{false: "device_close", true: "peer_stop"}[stopPeer], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				exec := serviceTestExecutor(t)
				p := newR2FlowPairWithExecutors(t, [2]*CryptoExecutor{exec, exec})
				p.dev[0].peers.RLock()
				var peer *Peer
				for _, v := range p.dev[0].peers.keyMap {
					peer = v
					break
				}
				p.dev[0].peers.RUnlock()
				if peer == nil {
					t.Fatal("missing configured peer")
				}
				time.Sleep(6 * time.Millisecond)
				done := make(chan error, 1)
				go func() { done <- peer.SendBuffers([][]byte{{0}}) }()
				synctest.Wait()
				select {
				case <-done:
					t.Fatal("SendBuffers bypassed control turn")
				default:
				}
				// Acquiring net proves the waiting SendBuffers did not hold RLock.
				locked := make(chan struct{})
				go func() { p.dev[0].net.Lock(); p.dev[0].net.Unlock(); close(locked) }()
				synctest.Wait()
				select {
				case <-locked:
				default:
					t.Fatal("policy waiter held network lock")
				}
				if stopPeer {
					peer.Stop()
				} else {
					p.dev[0].Close()
				}
				synctest.Wait()
				if err := <-done; !errors.Is(err, context.Canceled) {
					t.Fatalf("SendBuffers cancellation = %v", err)
				}
				if !time.Now().Before(exec.servicePolicy.epoch.Add(10 * time.Millisecond)) {
					t.Fatal("shutdown waited for a future quota")
				}
				p.close(t)
			})
		})
	}
}
