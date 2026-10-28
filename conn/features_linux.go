/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

func disableKCPGRO(conn *net.UDPConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var socketErr error
	err = raw.Control(func(fd uintptr) {
		socketErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO, 0)
	})
	if errors.Is(socketErr, unix.ENOPROTOOPT) || errors.Is(socketErr, unix.EOPNOTSUPP) {
		socketErr = nil
	}
	return errors.Join(err, socketErr)
}

func supportsUDPOffload(conn *net.UDPConn) (txOffload, rxOffload bool) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return
	}
	err = rc.Control(func(fd uintptr) {
		_, errSyscall := unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT)
		txOffload = errSyscall == nil
		opt, errSyscall := unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO)
		rxOffload = errSyscall == nil && opt == 1
	})
	if err != nil {
		return false, false
	}
	return txOffload, rxOffload
}
