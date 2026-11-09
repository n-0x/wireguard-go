package conn

import (
	"fmt"
	"net"
	"syscall"
)

// UDPSocket is an owned UDP socket used by StdNetBind. SyscallConn must refer
// to the same socket as all I/O methods, without duplicating the descriptor.
type UDPSocket interface {
	net.PacketConn
	ReadMsgUDP([]byte, []byte) (int, int, int, *net.UDPAddr, error)
	WriteMsgUDP([]byte, []byte, *net.UDPAddr) (int, int, error)
	SyscallConn() (syscall.RawConn, error)
	SetReadBuffer(int) error
	SetWriteBuffer(int) error
}

// UDPSocketFactory creates a fresh unconnected socket. On success StdNetBind
// owns it exclusively and closes it on rollback or Close. On error the factory
// must release any resources it created and return a nil socket.
type UDPSocketFactory func(string, *net.UDPAddr) (UDPSocket, error)

// NewStdNetBindWithSocketFactory selects an optional owned socket factory.
// A nil factory preserves the legacy NewStdNetBind socket setup.
func NewStdNetBindWithSocketFactory(factory UDPSocketFactory) Bind {
	b := NewStdNetBind().(*StdNetBind)
	b.socketFactory = factory
	return b
}

func (s *StdNetBind) listenSocket(network string, port int) (UDPSocket, int, error) {
	if s.socketFactory == nil {
		c, actual, err := listenNet(network, port)
		if err != nil {
			return nil, 0, err
		}
		return c, actual, nil
	}
	addr := &net.UDPAddr{Port: port}
	c, err := s.socketFactory(network, addr)
	if err != nil {
		return nil, 0, err
	}
	if c == nil {
		return nil, 0, fmt.Errorf("owned UDP factory returned nil socket")
	}
	raw, err := c.SyscallConn()
	if err == nil {
		for _, fn := range controlFns {
			if err = fn(network, c.LocalAddr().String(), raw, true); err != nil {
				break
			}
		}
	}
	if err != nil {
		c.Close()
		return nil, 0, err
	}
	local, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		c.Close()
		return nil, 0, fmt.Errorf("owned UDP socket has non-UDP address")
	}
	return c, local.Port, nil
}
