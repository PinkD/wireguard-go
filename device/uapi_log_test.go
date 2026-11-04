package device

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestUAPILogDoesNotEchoConfiguration(t *testing.T) {
	const secret = "DO_NOT_LOG_PRIVATE_KEY_OR_COMMAND"
	var mu sync.Mutex
	var output strings.Builder
	logf := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(&output, format, args...)
	}
	dev := &Device{log: &Logger{Verbosef: logf, Errorf: logf}}
	for _, input := range []string{secret, "private_key=" + secret, "listen_port=" + secret, "replace_peers=" + secret} {
		if err := dev.IpcSet(input); err == nil {
			t.Fatalf("unexpected valid input %q", input)
		}
	}
	a, b := net.Pipe()
	defer b.Close()
	done := make(chan struct{})
	go func() { dev.IpcHandle(a); close(done) }()
	b.SetDeadline(time.Now().Add(time.Second))
	b.Write([]byte(secret + "\n"))
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("invalid operation did not terminate")
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Contains(output.String(), secret) {
		t.Fatalf("configuration leaked to log: %s", output.String())
	}
	if !strings.Contains(output.String(), "errno=") {
		t.Fatal("diagnostic error code missing")
	}
}
