/* SPDX-License-Identifier: MIT */

package device

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun"
)

// CryptoExecutor shares transport encryption and decryption workers across
// devices. It limits concurrent crypto batches, not total CPU or packet WIP.
// Create it with NewCryptoExecutor; the zero value cannot accept devices.
type CryptoExecutor struct {
	mu            sync.Mutex
	cond          *sync.Cond
	registrations []*cryptoRegistration
	next          int // next device in the round-robin ring
	closing       bool
	workers       int
	done          chan struct{}
}

type cryptoRegistration struct {
	executor      *CryptoExecutor
	device        *Device // published under executor.mu after both queues exist
	nextDirection int
	active        [2]bool
	eof           [2]bool
}

type cryptoJob struct {
	registration *cryptoRegistration
	direction    int
	outbound     *QueueOutboundElementsContainer
	inbound      *QueueInboundElementsContainer
}

// NewCryptoExecutor starts workers shared by both transport directions.
// workers must be declared by the caller in [1, GOMAXPROCS]; it is not a CPU quota.
func NewCryptoExecutor(workers int) (*CryptoExecutor, error) {
	if workers < 1 || workers > runtime.GOMAXPROCS(0) {
		return nil, fmt.Errorf("crypto workers must be in [1, %d]", runtime.GOMAXPROCS(0))
	}
	exec := &CryptoExecutor{workers: workers, done: make(chan struct{})}
	exec.cond = sync.NewCond(&exec.mu)
	for i := 0; i < workers; i++ {
		go exec.run()
	}
	return exec, nil
}

// NewDeviceWithCryptoExecutor opts into shared crypto. An accepted device must
// be closed before executor.Close can finish. Rejection starts no device routines
// and leaves ownership of tunDevice and bind with the caller.
func NewDeviceWithCryptoExecutor(tunDevice tun.Device, bind conn.Bind, logger *Logger, exec *CryptoExecutor) (*Device, error) {
	if exec == nil {
		return nil, errors.New("nil crypto executor")
	}
	exec.mu.Lock()
	if exec.done == nil || exec.closing {
		exec.mu.Unlock()
		return nil, errors.New("crypto executor is not accepting devices")
	}
	registration := &cryptoRegistration{executor: exec}
	// Reserve admission before initialization; Close also waits for this device.
	exec.registrations = append(exec.registrations, registration)
	exec.mu.Unlock()
	return newDevice(tunDevice, bind, logger, registration), nil
}

// Close seals admission and waits for all accepted devices to close and drain.
// A context error only stops this wait: workers continue serving existing devices.
// Close may be called concurrently or retried after a context error.
func (exec *CryptoExecutor) Close(ctx context.Context) error {
	exec.mu.Lock()
	if exec.done == nil {
		exec.mu.Unlock()
		return errors.New("uninitialized crypto executor")
	}
	exec.closing = true
	exec.cond.Broadcast()
	exec.mu.Unlock()
	select {
	case <-exec.done:
		return nil
	default:
	}
	select {
	case <-exec.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (exec *CryptoExecutor) notify(_ *cryptoRegistration) {
	exec.mu.Lock()
	exec.cond.Broadcast()
	exec.mu.Unlock()
}

func (device *Device) enqueueEncryption(container *QueueOutboundElementsContainer) {
	device.queue.encryption.c <- container
	if device.crypto != nil {
		device.crypto.executor.notify(device.crypto)
	}
}

func (device *Device) enqueueDecryption(container *QueueInboundElementsContainer) {
	device.queue.decryption.c <- container
	if device.crypto != nil {
		device.crypto.executor.notify(device.crypto)
	}
}

// nextJob is called under mu. Queue publication precedes notify taking the same
// mutex, so a scan followed by cond.Wait cannot lose a publication or EOF wakeup.
// Scanning costs O(devices); each lane has at most one active batch.
func (exec *CryptoExecutor) nextJob() (cryptoJob, bool) {
	devices := len(exec.registrations)
	for offset := 0; offset < devices; offset++ {
		index := (exec.next + offset) % devices
		registration := exec.registrations[index]
		if registration.device == nil {
			continue
		}
		for turn := 0; turn < 2; turn++ {
			direction := (registration.nextDirection + turn) % 2
			if registration.active[direction] || registration.eof[direction] {
				continue
			}
			job := cryptoJob{registration: registration, direction: direction}
			if direction == 0 {
				select {
				case container, ok := <-registration.device.queue.encryption.c:
					if !ok {
						registration.eof[direction] = true
						exec.cond.Broadcast()
						continue
					}
					job.outbound = container
				default:
					continue
				}
			} else {
				select {
				case container, ok := <-registration.device.queue.decryption.c:
					if !ok {
						registration.eof[direction] = true
						exec.cond.Broadcast()
						continue
					}
					job.inbound = container
				default:
					continue
				}
			}
			registration.active[direction] = true
			registration.nextDirection = 1 - direction
			exec.next = (index + 1) % devices
			return job, true
		}
	}
	return cryptoJob{}, false
}

func (exec *CryptoExecutor) run() {
	var encryption encryptionScratch
	var decryption decryptionScratch
	exec.mu.Lock()
	defer func() {
		exec.workers--
		if exec.workers == 0 {
			close(exec.done)
		}
		exec.mu.Unlock()
	}()
	for {
		job, ok := exec.nextJob()
		if !ok {
			if exec.closing && len(exec.registrations) == 0 {
				return
			}
			exec.cond.Wait()
			continue
		}
		exec.mu.Unlock()
		// Retain registration independently: completion publishes the container to a
		// consumer which can immediately recycle it. Never inspect it after the helper.
		registration, direction := job.registration, job.direction
		if direction == 0 {
			registration.device.encryptBatch(job.outbound, &encryption)
		} else {
			registration.device.decryptBatch(job.inbound, &decryption)
		}
		exec.mu.Lock()
		registration.active[direction] = false
		exec.cond.Broadcast()
	}
}

// detachAndWait runs only after Device.Close has stopped producers and peers.
// Until both queue EOFs and active completions are observed, keep serving them.
func (exec *CryptoExecutor) detachAndWait(registration *cryptoRegistration) {
	exec.mu.Lock()
	defer exec.mu.Unlock()
	for !registration.eof[0] || !registration.eof[1] || registration.active[0] || registration.active[1] {
		exec.cond.Wait()
	}
	for i, current := range exec.registrations {
		if current != registration {
			continue
		}
		copy(exec.registrations[i:], exec.registrations[i+1:])
		last := len(exec.registrations) - 1
		exec.registrations[last] = nil
		exec.registrations = exec.registrations[:last]
		if exec.next > i {
			exec.next--
		}
		if exec.next >= len(exec.registrations) {
			exec.next = 0
		}
		break
	}
	exec.cond.Broadcast()
}
