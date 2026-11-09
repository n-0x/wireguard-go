//go:build !windows && !linux && !wasm

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func init() {
	controlFns = append(controlFns,
		func(network, address string, c syscall.RawConn, alreadyBound bool) error {
			return c.Control(func(fd uintptr) {
				_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, socketBufferSize)
				_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, socketBufferSize)
			})
		},

		func(network, address string, c syscall.RawConn, alreadyBound bool) error {
			var err error
			if network == "udp6" {
				c.Control(func(fd uintptr) {
					if !alreadyBound {
						err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1)
					} else {
						// net.ListenUDP("udp6") already sets this before bind.
						var only int
						only, err = unix.GetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY)
						if err == nil && only != 1 {
							err = unix.EINVAL
						}
					}
				})
			}
			return err
		},
	)
}
