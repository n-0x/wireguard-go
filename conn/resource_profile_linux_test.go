//go:build linux && r2resourceprofile

/* SPDX-License-Identifier: MIT */

package conn

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// These tests require real UDP_SEGMENT/UDP_GRO. A skip is not offload evidence.
// Socket staging deliberately keeps full-size slots126/127, like R2's adapter.
func TestR2KernelGROStaging(t *testing.T) {
	if os.Getenv("R2_GRO_TEST") != "1" {
		t.Skip("set R2_GRO_TEST=1 for real local Linux UDP offload tests")
	}
	for _, family := range []string{"udp4", "udp6"} {
		for _, shape := range []struct {
			name                 string
			segments, size, tail int
		}{
			{"maximum_count", 64, 1000, 1000},
			{"mtu1420_wire", 44, 1452, 1452},
			{"short_tail", 3, 1452, 31},
		} {
			t.Run(family+"/"+shape.name, func(t *testing.T) {
				b := NewStdNetBind().(*StdNetBind)
				fns, port, err := b.Open(0)
				if err != nil {
					t.Fatal(err)
				}
				defer b.Close()
				receiver, fn, offload, host := b.ipv4, fns[0], b.ipv4RxOffload, "127.0.0.1"
				if family == "udp6" {
					if b.ipv6 == nil {
						t.Skip("IPv6 unavailable")
					}
					receiver, fn, offload, host = b.ipv6, fns[len(fns)-1], b.ipv6RxOffload, "::1"
				}
				if !offload {
					t.Skip("kernel UDP_GRO unavailable")
				}
				sender, err := net.DialUDP(family, nil, &net.UDPAddr{IP: net.ParseIP(host), Port: int(port)})
				if err != nil {
					t.Fatal(err)
				}
				defer sender.Close()
				raw, err := sender.SyscallConn()
				if err != nil {
					t.Fatal(err)
				}
				var sockErr error
				if err = raw.Control(func(fd uintptr) {
					sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT, shape.size)
				}); err != nil {
					t.Fatal(err)
				}
				if sockErr != nil {
					t.Skipf("UDP_SEGMENT unavailable: %v", sockErr)
				}
				payload := make([]byte, (shape.segments-1)*shape.size+shape.tail)
				for i := range payload {
					payload[i] = byte(i/shape.size + 1)
				}
				if n, err := sender.Write(payload); err != nil || n != len(payload) {
					t.Fatalf("GSO write n=%d err=%v", n, err)
				}
				rxRaw, err := receiver.SyscallConn()
				if err != nil {
					t.Fatal(err)
				}
				peek, oob := make([]byte, 65535), make([]byte, 256)
				var n, nn, flags int
				deadline := time.Now().Add(time.Second)
				for {
					err = rxRaw.Control(func(fd uintptr) {
						n, nn, flags, _, sockErr = unix.Recvmsg(int(fd), peek, oob, unix.MSG_PEEK|unix.MSG_DONTWAIT)
					})
					if err != nil {
						t.Fatal(err)
					}
					if sockErr != unix.EAGAIN && sockErr != unix.EINTR {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("no loopback GSO datagram")
					}
					time.Sleep(time.Millisecond)
				}
				if sockErr != nil {
					t.Fatal(sockErr)
				}
				if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
					t.Fatalf("truncated GRO peek: flags=%d", flags)
				}
				controls, err := unix.ParseSocketControlMessage(oob[:nn])
				if err != nil {
					t.Fatal(err)
				}
				segmentSize := 0
				for _, c := range controls {
					if c.Header.Level == unix.IPPROTO_UDP && c.Header.Type == unix.UDP_GRO && len(c.Data) >= 2 {
						segmentSize = int(binary.NativeEndian.Uint16(c.Data))
					}
				}
				if n != len(payload) || segmentSize != shape.size {
					t.Skipf("kernel did not retain GRO aggregate: n=%d segment=%d", n, segmentSize)
				}
				if !bytes.Equal(peek[:n], payload) {
					t.Fatal("GRO aggregate changed")
				}
				bufs := make([][]byte, 128)
				for i := range bufs {
					size := 2016
					if i >= 126 {
						size = 65535
					}
					bufs[i] = make([]byte, size)
				}
				sizes, eps := make([]int, 128), make([]Endpoint, 128)
				type result struct {
					n   int
					err error
				}
				done := make(chan result, 1)
				go func() { n, err := fn(bufs, sizes, eps); done <- result{n, err} }()
				var got result
				select {
				case got = <-done:
				case <-time.After(time.Second):
					b.Close()
					<-done
					t.Fatal("StdNetBind GRO split did not finish")
				}
				if got.err != nil || got.n != shape.segments {
					t.Fatalf("split n=%d err=%v, want %d", got.n, got.err, shape.segments)
				}
				for i := range got.n {
					size := shape.size
					if i == got.n-1 {
						size = shape.tail
					}
					if sizes[i] != size || !bytes.Equal(bufs[i][:sizes[i]], payload[i*shape.size:i*shape.size+size]) {
						t.Fatalf("segment%d size=%d changed", i, sizes[i])
					}
					if eps[i] == nil || eps[i].DstToString() != sender.LocalAddr().String() {
						t.Fatalf("segment%d endpoint changed", i)
					}
				}
				t.Logf("real UDP_GRO aggregate=%d segment=%d delivered=%d with 2016-byte segment slots and 65535-byte staging", n, segmentSize, got.n)
			})
		}
	}
}

func TestR2GSOCapacity(t *testing.T) {
	for _, tc := range []struct {
		name       string
		size, want int
	}{
		{"full_mtu_loses_coalescing", 1452, 8},
		{"small_packets_still_coalesce", 128, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bufs := make([][]byte, 8)
			msgs := make([]ipv6.Message, 8)
			for i := range bufs {
				bufs[i] = make([]byte, tc.size, 2016)
				bufs[i][0] = byte(i + 1)
				msgs[i].Buffers = make([][]byte, 1)
				msgs[i].OOB = make([]byte, 0, 2)
			}
			a := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
			got := coalesceMessages(a, &StdNetEndpoint{}, bufs, msgs, mockSetGSOSize)
			if got != tc.want {
				t.Fatalf("coalesced into%d messages, want%d", got, tc.want)
			}
		})
	}
}

func TestR2KernelGSOSendAndDisabledFallback(t *testing.T) {
	if os.Getenv("R2_GRO_TEST") != "1" {
		t.Skip("set R2_GRO_TEST=1 for real local Linux UDP offload tests")
	}
	for _, disabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("offload_disabled_%v", disabled), func(t *testing.T) {
			b := NewStdNetBind().(*StdNetBind)
			_, _, err := b.Open(0)
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			if !disabled && !b.ipv4TxOffload {
				t.Skip("kernel UDP_SEGMENT unavailable")
			}
			if disabled {
				b.ipv4TxOffload = false
			}
			rx, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer rx.Close()
			if err = rx.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			ep, err := b.ParseEndpoint(rx.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			for _, size := range []int{1452, 128} {
				bufs := make([][]byte, 8)
				for i := range bufs {
					bufs[i] = bytes.Repeat([]byte{byte(i + 1)}, size)
					copyBuf := make([]byte, size, 2016)
					copy(copyBuf, bufs[i])
					bufs[i] = copyBuf
				}
				if err = b.Send(bufs, ep); err != nil {
					t.Fatal(err)
				}
				for i := range bufs {
					got := make([]byte, 65535)
					n, _, err := rx.ReadFromUDP(got)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(got[:n], bufs[i]) {
						t.Fatalf("datagram%d payload changed", i)
					}
				}
			}
			t.Logf("real UDP delivered MTU-sized and small packets; offload disabled=%v", disabled)
		})
	}
}
