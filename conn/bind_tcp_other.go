//go:build !linux

package conn

func setTCPCongestionControl(fd int, cc string) error {
	return nil
}
