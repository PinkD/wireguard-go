//go:build !linux && !openbsd && !freebsd

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package conn

import "net"

func (s *StdNetBind) SetMark(mark uint32) error {
	return nil
}

func setTCPMark(_ *net.TCPConn, _ uint32) error {
	return nil
}
