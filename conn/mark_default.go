//go:build !linux && !openbsd && !freebsd

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package conn

func (s *StdNetBind) SetMark(mark uint32) error {
	return nil
}

func (t *TcpBind) SetMark(mark uint32) error {
	return nil
}
