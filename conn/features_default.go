//go:build !linux
// +build !linux

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

func supportsUDPOffload(_ UDPSocket) (txOffload, rxOffload bool) {
	return
}
