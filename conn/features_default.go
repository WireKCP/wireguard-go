//go:build !linux
// +build !linux

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package conn

import "net"

func disableKCPGRO(conn *net.UDPConn) error { return nil }

func supportsUDPOffload(conn *net.UDPConn) (txOffload, rxOffload bool) {
	return
}
