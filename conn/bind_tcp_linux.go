//go:build linux

package conn

import "golang.org/x/sys/unix"

func setTCPCongestionControl(fd int, cc string) error {
	return unix.SetsockoptString(fd, unix.IPPROTO_TCP, unix.TCP_CONGESTION, cc)
}
