/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/conn/bindtest"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

type pausedOpenBind struct {
	conn.Bind
	entered chan struct{}
	release chan struct{}
}

func (b *pausedOpenBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	close(b.entered)
	<-b.release
	return b.Bind.Open(port)
}

func TestConcurrentUpClose(t *testing.T) {
	tun := tuntest.NewChannelTUN()
	<-tun.TUN().Events() // drive Up explicitly at the controlled point below
	bind := &pausedOpenBind{
		Bind:    bindtest.NewChannelBinds()[0],
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(bind.release) }) }
	defer release()
	dev := NewDevice(tun.TUN(), bind, NewLogger(LogLevelSilent, ""))
	upDone := make(chan error, 1)
	go func() { upDone <- dev.Up() }()
	select {
	case <-bind.entered: // Up now holds state, before its ipcMutex acquisition
	case <-time.After(5 * time.Second):
		t.Fatal("Up did not reach the controlled bind")
	}
	closeDone := make(chan struct{})
	go func() { dev.Close(); close(closeDone) }()

	// Wait until Close actually attempts its lock. Merely starting its
	// goroutine and sleeping would make the old lock inversion intermittent.
	deadline := time.Now().Add(5 * time.Second)
	for {
		stack := make([]byte, 256<<10)
		stack = stack[:runtime.Stack(stack, true)]
		blocked := false
		for _, goroutine := range strings.Split(string(stack), "\n\n") {
			if strings.Contains(goroutine, "(*Device).Close(") && strings.Contains(goroutine, "sync.Mutex.Lock") {
				blocked = true
				break
			}
		}
		if blocked {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Close did not reach the state transition lock")
		}
		time.Sleep(time.Millisecond)
	}
	release()
	select {
	case err := <-upDone:
		if err != nil {
			t.Fatalf("Up failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Up and Close deadlocked while acquiring state/ipcMutex")
	}
	select {
	case <-closeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not finish after Up")
	}
	if !dev.isClosed() {
		t.Fatal("concurrent shutdown did not leave the device closed")
	}
}
