package conn

import (
	"bytes"
	"errors"
	"net"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type countedSocket struct {
	*net.UDPConn
	closes atomic.Int32
}

func (s *countedSocket) Close() error { s.closes.Add(1); return s.UDPConn.Close() }

func TestOwnedSocketFactory(t *testing.T) {
	var sockets []*countedSocket
	factory := func(network string, addr *net.UDPAddr) (UDPSocket, error) {
		c, err := net.ListenUDP(network, addr)
		if err != nil {
			return nil, err
		}
		s := &countedSocket{UDPConn: c}
		sockets = append(sockets, s)
		return s, nil
	}
	b := NewStdNetBindWithSocketFactory(factory)
	fns, port, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if len(sockets) != len(fns) || len(sockets) == 0 {
		t.Fatalf("factory ignored: sockets=%d receivers=%d", len(sockets), len(fns))
	}
	for i, s := range sockets {
		if err := s.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		host := "127.0.0.1"
		if s.LocalAddr().(*net.UDPAddr).IP.To4() == nil {
			host = "::1"
		}
		ep, err := b.ParseEndpoint(net.JoinHostPort(host, strconv.Itoa(int(port))))
		if err != nil {
			t.Fatal(err)
		}
		payload := bytes.Repeat([]byte{byte(i + 1)}, 1400)
		if err := b.Send([][]byte{payload}, ep); err != nil {
			t.Fatal(err)
		}
		bufs := make([][]byte, b.BatchSize())
		for j := range bufs {
			bufs[j] = make([]byte, 65535)
		}
		sizes := make([]int, len(bufs))
		eps := make([]Endpoint, len(bufs))
		n, err := fns[i](bufs, sizes, eps)
		if err != nil || n != 1 || sizes[0] != len(payload) || !bytes.Equal(bufs[0][:sizes[0]], payload) {
			t.Fatalf("loopback n=%d err=%v", n, err)
		}
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	for _, s := range sockets {
		if s.closes.Load() != 1 {
			t.Fatalf("close count=%d", s.closes.Load())
		}
	}
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
}

func TestOwnedSocketFactoryRollback(t *testing.T) {
	sentinel := errors.New("factory failure")
	var opened *countedSocket
	b := NewStdNetBindWithSocketFactory(func(network string, addr *net.UDPAddr) (UDPSocket, error) {
		if network == "udp6" {
			return nil, sentinel
		}
		c, err := net.ListenUDP(network, addr)
		if err != nil {
			return nil, err
		}
		opened = &countedSocket{UDPConn: c}
		return opened, nil
	})
	if _, _, err := b.Open(0); !errors.Is(err, sentinel) {
		t.Fatalf("error=%v", err)
	}
	if opened == nil || opened.closes.Load() != 1 {
		t.Fatal("rollback did not close owned IPv4")
	}
	b.Close()
	if opened.closes.Load() != 1 {
		t.Fatal("rollback double close")
	}
}

func TestOwnedSocketIPv4Unavailable(t *testing.T) {
	b := NewStdNetBindWithSocketFactory(func(network string, addr *net.UDPAddr) (UDPSocket, error) { return nil, syscall.EAFNOSUPPORT })
	if _, _, err := b.Open(0); !errors.Is(err, syscall.EAFNOSUPPORT) {
		t.Fatalf("error=%v", err)
	}
}

func TestOwnedSocketSingleFamily(t *testing.T) {
	for _, family := range []string{"udp4", "udp6"} {
		t.Run(family, func(t *testing.T) {
			b := NewStdNetBindWithSocketFactory(func(network string, addr *net.UDPAddr) (UDPSocket, error) {
				if network != family {
					return nil, syscall.EAFNOSUPPORT
				}
				return net.ListenUDP(network, addr)
			})
			defer b.Close()
			fns, port, err := b.Open(0)
			if err != nil || len(fns) != 1 || port == 0 {
				t.Fatalf("single family receivers=%d port=%d err=%v", len(fns), port, err)
			}
		})
	}
}

func TestOwnedSocketCloseUnblocks(t *testing.T) {
	b := NewStdNetBindWithSocketFactory(func(network string, addr *net.UDPAddr) (UDPSocket, error) { return net.ListenUDP(network, addr) })
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	done := make(chan error, len(fns))
	for _, fn := range fns {
		go func() {
			bufs := make([][]byte, b.BatchSize())
			for i := range bufs {
				bufs[i] = make([]byte, 65535)
			}
			_, err := fn(bufs, make([]int, len(bufs)), make([]Endpoint, len(bufs)))
			done <- err
		}()
	}
	b.Close()
	for range fns {
		select {
		case err := <-done:
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("read close: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("reader did not join")
		}
	}
}

func ownedSocketTestBind() *StdNetBind {
	return NewStdNetBindWithSocketFactory(func(network string, addr *net.UDPAddr) (UDPSocket, error) { return net.ListenUDP(network, addr) }).(*StdNetBind)
}

type rawErrorSocket struct {
	*countedSocket
	err error
}

func (s *rawErrorSocket) SyscallConn() (syscall.RawConn, error) { return nil, s.err }

func TestOwnedSocketConfigurationRollback(t *testing.T) {
	sentinel := errors.New("raw unavailable")
	var opened *countedSocket
	b := NewStdNetBindWithSocketFactory(func(network string, addr *net.UDPAddr) (UDPSocket, error) {
		c, err := net.ListenUDP(network, addr)
		if err != nil {
			return nil, err
		}
		opened = &countedSocket{UDPConn: c}
		return &rawErrorSocket{opened, sentinel}, nil
	})
	defer b.Close()
	if _, _, err := b.Open(0); !errors.Is(err, sentinel) {
		t.Fatalf("error=%v", err)
	}
	if opened == nil || opened.closes.Load() != 1 {
		t.Fatal("configuration rollback lost socket ownership")
	}
}

func TestOwnedSocketPortRetry(t *testing.T) {
	var sockets []*countedSocket
	retries := 0
	b := NewStdNetBindWithSocketFactory(func(network string, addr *net.UDPAddr) (UDPSocket, error) {
		if network == "udp6" && retries == 0 {
			retries++
			return nil, syscall.EADDRINUSE
		}
		c, err := net.ListenUDP(network, addr)
		if err != nil {
			return nil, err
		}
		s := &countedSocket{UDPConn: c}
		sockets = append(sockets, s)
		return s, nil
	})
	defer b.Close()
	if _, port, err := b.Open(0); err != nil || port == 0 {
		t.Fatalf("port=%d err=%v", port, err)
	}
	if len(sockets) != 3 || sockets[0].closes.Load() != 1 {
		t.Fatalf("retry sockets=%d", len(sockets))
	}
	b.Close()
	for _, s := range sockets {
		if s.closes.Load() != 1 {
			t.Fatalf("close count=%d", s.closes.Load())
		}
	}
}
