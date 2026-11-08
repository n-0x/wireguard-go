//go:build go1.25

/* SPDX-License-Identifier: MIT */

package device

import (
	"context"
	"testing"
	"testing/synctest"
)

func TestCryptoExecutorSleepingWorkersObserveEOF(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		exec, devices := newCryptoTestDevices(t, 1)
		synctest.Wait() // queues empty, worker durably blocked in cond.Wait
		done := make(chan struct{})
		go func() { devices[0].Close(); close(done) }()
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("empty queue EOF did not wake the sleeping worker")
		}
		cryptoQueueTX(t, devices[1], cryptoCipher(t), 1)()
		devices[1].Close()
		if err := exec.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
}
