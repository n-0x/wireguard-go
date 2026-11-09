package conn

import (
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"
)

// Pin the single, synchronously used pool object: race builds may discard Put.
// Assert the full destination sent by StdNetBind, not merely loopback delivery
// (some kernels route the accidentally truncated unspecified address locally).
func TestOwnedSocketDestinationReuse(t *testing.T) {
	for _, order := range []struct {
		name  string
		hosts []string
	}{
		{"v4_then_v6", []string{"127.0.0.1", "::1", "127.0.0.1", "::1"}},
		{"v6_then_v4", []string{"::1", "127.0.0.1", "::1", "127.0.0.1"}},
	} {
		t.Run(order.name, func(t *testing.T) {
			b := ownedSocketTestBind()
			_, port, err := b.Open(0)
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			// Start at len4/cap16 even for the v6-first case to make the failure
			// deterministic when sync.Pool.Get invokes New under -race.
			used := &net.UDPAddr{IP: make(net.IP, 4, 16)}
			b.udpAddrPool = sync.Pool{New: func() any { return used }}
			for i, host := range order.hosts {
				want := netip.MustParseAddr(host)
				ep, err := b.ParseEndpoint(net.JoinHostPort(host, strconv.Itoa(int(port))))
				if err != nil {
					t.Fatal(err)
				}
				sendErr := b.Send([][]byte{make([]byte, 32)}, ep)
				got, ok := netip.AddrFromSlice(used.IP)
				if !ok || got != want {
					t.Fatalf("step %d: pooled destination bytes changed (family6=%t)", i, want.Is6())
				}
				if sendErr != nil {
					t.Fatal(sendErr)
				}
			}
		})
	}
}
