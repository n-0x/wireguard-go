/* SPDX-License-Identifier: MIT */

package device

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrServicePolicyClosed means the owner has sealed the shared service policy.
var ErrServicePolicyClosed = errors.New("service policy closed")

var errServicePolicyInterrupted = errors.New("service policy wait interrupted")

// ServicePolicy withholds new WG work during the control part of each period.
// It offers scheduling opportunities, not an OS CPU reservation or a latency
// guarantee. Already running batches and work outside the hooks may continue.
// Backpressure, UDP drops and lower throughput are expected under saturation.
//
// The process owner must share one instance across all participating executors
// and retain it across executor/device epochs. Executors do not close it.
// The zero value is invalid. A policy starts no goroutine or timer while idle.
type ServicePolicy struct {
	period, dataTurn time.Duration
	epoch            time.Time // retains time.Now's monotonic component
	mu               sync.Mutex
	closed           bool
	waiters          int
	wake             chan struct{}
	timer            *time.Timer
	generation       uint64
}

// ServicePolicySnapshot describes policy ownership and activity without packet
// contents or identities. Epoch is fixed at construction and is not a quota.
type ServicePolicySnapshot struct {
	Epoch               time.Time
	Period, DataTurn    time.Duration
	Waiters             int
	TimerActive, Closed bool
}

// Snapshot returns a coherent diagnostic view; it never starts a timer.
func (p *ServicePolicy) Snapshot() ServicePolicySnapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	return ServicePolicySnapshot{Epoch: p.epoch, Period: p.period, DataTurn: p.dataTurn,
		Waiters: p.waiters, TimerActive: p.timer != nil, Closed: p.closed}
}

// NewServicePolicy fixes a process epoch and a positive data/control split.
// The first dataTurn of each period permits WG promotion; the remainder yields
// that promotion. New devices/executors never reset this clock.
func NewServicePolicy(period, dataTurn time.Duration) (*ServicePolicy, error) {
	if period <= 0 || dataTurn <= 0 || dataTurn >= period {
		return nil, errors.New("service policy requires 0 < data turn < period")
	}
	return &ServicePolicy{period: period, dataTurn: dataTurn, epoch: time.Now()}, nil
}

func (p *ServicePolicy) validate() error {
	if p == nil || p.period <= 0 || p.dataTurn <= 0 || p.dataTurn >= p.period || p.epoch.IsZero() {
		return errors.New("uninitialized service policy")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrServicePolicyClosed
	}
	return nil
}

// Wait waits for a data opportunity or cancellation. It must be called before
// taking network, peer, send, state or completion locks. It does not grant quota
// in advance: every return rechecks the monotonic phase, including late wakes.
// All blocked callers share one timer and broadcast; the last canceled waiter
// removes the timer. Close wakes callers with ErrServicePolicyClosed.
func (p *ServicePolicy) Wait(ctx context.Context) error {
	return p.wait(ctx, nil)
}

// allowed is advisory at a batch boundary. A sealed policy still permits
// accepted completions to drain; ingress waiters themselves return an error.
func (p *ServicePolicy) allowed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closed || time.Since(p.epoch)%p.period < p.dataTurn
}

func (p *ServicePolicy) wait(ctx context.Context, interrupt <-chan struct{}) error {
	if err := p.validate(); err != nil {
		return err
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return ErrServicePolicyClosed
		}
		phase := time.Since(p.epoch) % p.period
		if phase < p.dataTurn {
			p.mu.Unlock()
			return nil
		}
		if p.timer == nil {
			p.wake = make(chan struct{})
			p.generation++
			generation := p.generation
			p.timer = time.AfterFunc(p.period-phase, func() { p.broadcast(generation) })
		}
		wake := p.wake
		p.waiters++
		p.mu.Unlock()
		interrupted := false
		select {
		case <-wake:
		case <-ctx.Done():
		case <-interrupt:
			interrupted = true
		}
		p.mu.Lock()
		p.waiters--
		if p.waiters == 0 && p.timer != nil {
			p.timer.Stop()
			p.timer, p.wake = nil, nil
			p.generation++ // an expired callback may still be waiting for mu
		}
		p.mu.Unlock()
		if interrupted {
			return errServicePolicyInterrupted
		}
	}
}

func (p *ServicePolicy) broadcast(generation uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if generation != p.generation {
		return
	}
	p.timer = nil
	if p.wake != nil {
		close(p.wake)
		p.wake = nil
	}
}

// Close seals the policy and wakes its waiters. It is idempotent. The process
// owner calls it during shutdown; accepted crypto completions still drain.
func (p *ServicePolicy) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	p.generation++
	if p.timer != nil {
		p.timer.Stop()
		p.timer = nil
	}
	if p.wake != nil {
		close(p.wake)
		p.wake = nil
	}
}

// serviceRun belongs to a device, peer run or bind run. Cancellation only wakes
// this run; it never resets or closes the process policy.
type serviceRun struct {
	policy *ServicePolicy
	ctx    context.Context
	cancel context.CancelFunc
}

func newServiceRun(policy *ServicePolicy, parent context.Context) *serviceRun {
	ctx, cancel := context.WithCancel(parent)
	return &serviceRun{policy: policy, ctx: ctx, cancel: cancel}
}

func (r *serviceRun) wait() error {
	if r == nil {
		return nil
	}
	return r.policy.Wait(r.ctx)
}

func (peer *Peer) waitService() error {
	if run := peer.service.Load(); run != nil {
		return run.wait()
	}
	return peer.device.service.wait()
}
