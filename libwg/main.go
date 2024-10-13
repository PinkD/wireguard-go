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
	"strings"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

const (
	ExitSetupSuccess = 0
	ExitSetupFailed  = 1
)

var wgDevice *device.Device

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
//
//export startWg
func startWg(logLevel, protocol C.int, interfaceName *C.cchar_t) C.int {
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
		wgDevice = device.NewDevice(tunDevice, conn.NewTCPBind(), logger)
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

func main() {
	panic("this is a lib, cannot be run")
}
