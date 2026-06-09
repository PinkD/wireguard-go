package conn

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestTCPBindSendReceive(t *testing.T) {
	listener := NewTCPBind().(*TcpBind)
	fns, _, err := listener.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	// Get the actual listening port
	port := listener.listener.Addr().(*net.TCPAddr).Port

	client := NewTCPBind().(*TcpBind)
	_, _, err = client.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	ep, err := client.ParseEndpoint(fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}

	packets := []string{
		"hello world",
		"packet 2",
		strings.Repeat("X", 4096),
		strings.Repeat("Y", MaxSegmentSize),
	}

	bufs := make([][]byte, 1)
	sizes := make([]int, 1)
	eps := make([]Endpoint, 1)

	for i, want := range packets {
		err := client.Send([][]byte{[]byte(want)}, ep)
		if err != nil {
			t.Fatalf("send packet %d: %v", i, err)
		}

		bufs[0] = make([]byte, MaxSegmentSize)
		n, err := fns[0](bufs, sizes, eps)
		if err != nil {
			t.Fatalf("recv packet %d: %v", i, err)
		}
		if n != 1 {
			t.Fatalf("expected 1 packet, got %d", n)
		}
		if sizes[0] != len(want) {
			t.Fatalf("packet %d size mismatch: got %d, want %d", i, sizes[0], len(want))
		}
		got := string(bufs[0][:sizes[0]])
		if got != want {
			t.Fatalf("packet %d content mismatch:\ngot  %q\nwant %q", i, got, want)
		}
	}
}

func TestTCPBindReceiveOversized(t *testing.T) {
	listener := NewTCPBind().(*TcpBind)
	_, _, err := listener.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	port := listener.listener.Addr().(*net.TCPAddr).Port

	// Directly dial and send a malformed length header
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	var l reqLen
	l.FromLen(MaxSegmentSize + 1)
	_, err = conn.Write(l[:])
	if err != nil {
		t.Fatal(err)
	}

	// Give the listener time to process and close the connection
	time.Sleep(100 * time.Millisecond)

	// Verify the connection is closed by trying to read (should get EOF)
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("expected connection to be closed after oversized packet")
	}
}
