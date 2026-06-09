package main

/*
#define LogLevelSilent  0
#define LogLevelError   1
#define LogLevelVerbose 2

#define ExitSetupSuccess  0
#define ExitSetupFailed   1

typedef const char cchar_t;
*/
import "C"

import (
	"errors"
	"fmt"
	// "net/http"
	// _ "net/http/pprof"
	"net/netip"
	"strings"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	ExitSetupSuccess = 0
	ExitSetupFailed  = 1
)

var wgDevice *device.Device

// tnet is the userspace network stack used in netstack (SOCKS5) mode.
// It is nil when running in the normal kernel-TUN mode.
var tnet *netstack.Net

//export uapi
func uapi(cmdStr *C.cchar_t) *C.char {
	content := C.GoString(cmdStr)
	cmds := strings.Split(content, "\n")
	var result string
	switch cmds[0] {
	case "set=1":
		logger.Verbosef("set uapi")
		content := strings.TrimPrefix(content, "set=1\n")
		err := wgDevice.IpcSetOperation(strings.NewReader(content))
		var status *device.IPCError
		switch {
		case err == nil:
			result = fmt.Sprintf("errno=0\n\n")
		case !errors.As(err, &status):
			result = fmt.Sprintf("errno=%d\n\n", ipc.IpcErrorUnknown)
		default:
			result = fmt.Sprintf("errno=%d\n\n", status.ErrorCode())
		}
	case "get=1":
		logger.Verbosef("get uapi")
		var err error
		result, err = wgDevice.IpcGet()
		var status *device.IPCError
		switch {
		case err == nil:
			result += fmt.Sprintf("errno=0\n\n")
		case !errors.As(err, &status):
			result += fmt.Sprintf("errno=%d\n\n", ipc.IpcErrorUnknown)
		default:
			result += fmt.Sprintf("errno=%d\n\n", status.ErrorCode())
		}
	default:
		logger.Verbosef("unknown uapi")
		result = fmt.Sprintf("errno=%d\n\n", ipc.IpcErrorUnknown)
	}
	return C.CString(result)
}

var logger *device.Logger

//export stopWg
func stopWg() {
	if wgDevice != nil {
		wgDevice.Close()
		logger.Verbosef("Shutting down")
	}
}

// startWg param:
//
//	protocol:
//	  0 for udp (default)
//	  1 for tcp (default)
//	congestionControl:
//	  TCP congestion control algorithm name, e.g. "bbr", "cubic"
//	  ignored when protocol is not tcp
//
//export startWg
func startWg(logLevel, protocol C.int, interfaceName, congestionControl *C.cchar_t) C.int {
	name := C.GoString(interfaceName)
	logger = device.NewLogger(
		int(logLevel),
		fmt.Sprintf("wg-corplink(%s) ", name),
	)

	tunDevice, err := tun.CreateTUN(name, device.DefaultMTU)
	if err == nil {
		realInterfaceName, err := tunDevice.Name()
		if err == nil {
			name = realInterfaceName
		}
	}

	logger.Verbosef("Starting wg-corplink version %s", Version)

	if err != nil {
		logger.Errorf("Failed to create TUN device: %v", err)
		return ExitSetupFailed
	}

	switch protocol {
	case 0:
		wgDevice = device.NewDevice(tunDevice, conn.NewDefaultBind(), logger)
	case 1:
		tcpBind := conn.NewTCPBind().(*conn.TcpBind)
		if cc := C.GoString(congestionControl); cc != "" {
			tcpBind.SetCongestionControl(cc)
		}
		wgDevice = device.NewDevice(tunDevice, tcpBind, logger)
	default:
		logger.Errorf("Protocol %d not supported", protocol)
		return ExitSetupFailed
	}

	//go func() {
	//	_ = http.ListenAndServe("localhost:6060", nil)
	//}()

	logger.Verbosef("Device %s started", name)
	ret := upDeviceForWindows(wgDevice)
	return C.int(ret)
}

// parseAddrList parses a comma-separated list of IPs or CIDRs (e.g.
// "100.64.0.2/19,fd00::2/128") into a slice of netip.Addr, dropping any
// prefix length. Empty entries are skipped.
func parseAddrList(s string) ([]netip.Addr, error) {
	var addrs []netip.Addr
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "/") {
			prefix, err := netip.ParsePrefix(part)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", part, err)
			}
			addrs = append(addrs, prefix.Addr())
		} else {
			addr, err := netip.ParseAddr(part)
			if err != nil {
				return nil, fmt.Errorf("invalid IP %q: %w", part, err)
			}
			addrs = append(addrs, addr)
		}
	}
	return addrs, nil
}

// startWgNetstack brings up WireGuard entirely in userspace using gVisor's
// netstack (no kernel TUN device, no system routes, no root) and exposes a
// SOCKS5 proxy. Outbound connections accepted by the proxy are dialed through
// the tunnel via tnet.DialContext.
//
//	protocol:          0 for udp (default), 1 for tcp
//	addresses:         comma-separated interface IPs/CIDRs assigned by the server
//	dnsServers:        comma-separated DNS server IPs (resolved inside the tunnel)
//	socksListen:       listen address for the SOCKS5 proxy, e.g. "0.0.0.0:1080"
//	socksUser:         SOCKS5 username; empty disables authentication
//	socksPass:         SOCKS5 password (used only when socksUser is non-empty)
//	mtu:               interface MTU (<=0 uses the default)
//	congestionControl: TCP congestion control algorithm name, ignored for udp
//
//export startWgNetstack
func startWgNetstack(logLevel, protocol C.int, addresses, dnsServers, socksListen, socksUser, socksPass, congestionControl *C.cchar_t, mtu C.int) C.int {
	logger = device.NewLogger(int(logLevel), "wg-corplink(netstack) ")
	logger.Verbosef("Starting wg-corplink version %s (netstack/socks5 mode)", Version)

	addrs, err := parseAddrList(C.GoString(addresses))
	if err != nil {
		logger.Errorf("Failed to parse interface addresses: %v", err)
		return ExitSetupFailed
	}
	if len(addrs) == 0 {
		logger.Errorf("No interface address provided for netstack mode")
		return ExitSetupFailed
	}
	dns, err := parseAddrList(C.GoString(dnsServers))
	if err != nil {
		logger.Errorf("Failed to parse dns servers: %v", err)
		return ExitSetupFailed
	}

	m := int(mtu)
	if m <= 0 {
		m = device.DefaultMTU
	}

	tunDevice, netStack, err := netstack.CreateNetTUNWithCC(addrs, dns, m, C.GoString(congestionControl))
	if err != nil {
		logger.Errorf("Failed to create netstack TUN device: %v", err)
		return ExitSetupFailed
	}
	tnet = netStack

	switch protocol {
	case 0:
		wgDevice = device.NewDevice(tunDevice, conn.NewDefaultBind(), logger)
	case 1:
		tcpBind := conn.NewTCPBind().(*conn.TcpBind)
		if cc := C.GoString(congestionControl); cc != "" {
			tcpBind.SetCongestionControl(cc)
		}
		wgDevice = device.NewDevice(tunDevice, tcpBind, logger)
	default:
		logger.Errorf("Protocol %d not supported", protocol)
		return ExitSetupFailed
	}

	if err := wgDevice.Up(); err != nil {
		logger.Errorf("Failed to bring up netstack device: %v", err)
		return ExitSetupFailed
	}

	listen := C.GoString(socksListen)
	user := C.GoString(socksUser)
	pass := C.GoString(socksPass)
	if err := startSocks5(listen, user, pass, netStack, logger); err != nil {
		logger.Errorf("Failed to start socks5 proxy on %s: %v", listen, err)
		return ExitSetupFailed
	}
	logger.Verbosef("socks5 proxy listening on %s", listen)
	return ExitSetupSuccess
}

func main() {
	panic("this is a lib, cannot be run")
}
