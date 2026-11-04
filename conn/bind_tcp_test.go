package conn

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestReqLen(t *testing.T) {
	for _, n := range []uint32{0, 123456789, 65535, 0xffffffff} {
		var l reqLen
		l.FromLen(int(n))
		if l.Len() != n {
			t.Fatalf("%d != %d", l.Len(), n)
		}
	}
}

func TestTCPFrameValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
		want error
	}{
		{"zero", []byte{0, 0, 0, 0}, errInvalidTCPFrame},
		{"oversize", []byte{0, 0, 1, 0}, errInvalidTCPFrame},
		{"maxUint32", []byte{255, 255, 255, 255}, errInvalidTCPFrame},
		{"shortHeader", []byte{1, 0}, io.ErrUnexpectedEOF},
		{"shortBody", []byte{3, 0, 0, 0, 1}, io.ErrUnexpectedEOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			go func() { b.Write(tc.data); b.Close() }()
			_, err := readTCPFrame(a, make([]byte, MaxSegmentSize), time.Second, time.Second)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestTCPPartialFrameDeadline(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go b.Write([]byte{1})
	_, err := readTCPFrame(a, make([]byte, 10), time.Second, 20*time.Millisecond)
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("partial header did not time out: %v", err)
	}
}

func openTCPClient(t *testing.T) (*TcpBind, ReceiveFunc) {
	t.Helper()
	b := NewTCPClientBind().(*TcpBind)
	fns, port, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	if port != 0 || b.state.listener != nil {
		t.Fatal("client bind opened an inbound listener")
	}
	t.Cleanup(func() { b.Close() })
	return b, fns[0]
}

func loopbackTCP(t *testing.T) *net.TCPListener {
	t.Helper()
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

func receiveOne(fn ReceiveFunc) ([]byte, error) {
	buf := make([]byte, MaxSegmentSize)
	sizes := make([]int, 1)
	_, err := fn([][]byte{buf}, sizes, make([]Endpoint, 1))
	return buf[:sizes[0]], err
}

func TestTCPClientBidirectionalAndConcurrentWrites(t *testing.T) {
	bind, recv := openTCPClient(t)
	ln := loopbackTCP(t)
	ep, _ := bind.ParseEndpoint(ln.Addr().String())
	const count = 24
	serverDone := make(chan error, 1)
	go func() {
		c, err := ln.AcceptTCP()
		if err != nil {
			serverDone <- err
			return
		}
		defer c.Close()
		buf := make([]byte, MaxSegmentSize)
		for i := 0; i < count; i++ {
			n, err := readTCPFrame(c, buf, time.Second, time.Second)
			// Concurrent Send order is unspecified; each frame must stay intact.
			if err != nil || n != 1024 || !bytes.Equal(buf[:n], bytes.Repeat(buf[:1], n)) {
				serverDone <- errors.New("corrupt concurrent frame")
				return
			}
			var header reqLen
			header.FromLen(n)
			buffers := net.Buffers{header[:], buf[:n]}
			if _, err := buffers.WriteTo(c); err != nil {
				serverDone <- err
				return
			}
		}
		serverDone <- nil
	}()
	var writers sync.WaitGroup
	for i := 0; i < count; i++ {
		writers.Add(1)
		go func(v byte) {
			defer writers.Done()
			if err := bind.Send([][]byte{bytes.Repeat([]byte{v}, 1024)}, ep); err != nil {
				t.Errorf("Send: %v", err)
			}
		}(byte(i))
	}
	seen := make(map[byte]bool)
	for i := 0; i < count; i++ {
		data, err := receiveOne(recv)
		if err != nil || len(data) != 1024 || !bytes.Equal(data, bytes.Repeat(data[:1], len(data))) {
			t.Fatalf("reply frame corrupt: %v", err)
		}
		if seen[data[0]] {
			t.Fatal("duplicate reply (receive buffer reused before copy)")
		}
		seen[data[0]] = true
	}
	writers.Wait()
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestTCPInvalidPeerEvictedAndReconnect(t *testing.T) {
	bind, recv := openTCPClient(t)
	ln := loopbackTCP(t)
	ep, _ := bind.ParseEndpoint(ln.Addr().String())
	if err := bind.Send([][]byte{{1}}, ep); err != nil {
		t.Fatal(err)
	}
	bad, err := ln.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	bad.Write([]byte{255, 255, 255, 255})
	deadline := time.Now().Add(time.Second)
	for {
		bind.state.mu.Lock()
		n := len(bind.state.conns)
		bind.state.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("invalid connection retained in map")
		}
		time.Sleep(time.Millisecond)
	}
	if err := bind.Send([][]byte{{2}}, ep); err != nil {
		t.Fatal(err)
	}
	good, err := ln.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer good.Close()
	good.Write([]byte{1, 0, 0, 0, 3})
	if got, err := receiveOne(recv); err != nil || !bytes.Equal(got, []byte{3}) {
		t.Fatalf("reconnect: %v %v", got, err)
	}
}

func TestTCPCloseUnblocksQueuedFrameAndReopen(t *testing.T) {
	bind, oldRecv := openTCPClient(t)
	ln := loopbackTCP(t)
	ep, _ := bind.ParseEndpoint(ln.Addr().String())
	if err := bind.Send([][]byte{{1}}, ep); err != nil {
		t.Fatal(err)
	}
	c, err := ln.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte{1, 0, 0, 0, 2})
	done := make(chan struct{})
	go func() { bind.Close(); bind.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close blocked on undelivered frame")
	}
	if _, _, err := bind.Open(0); err != nil {
		t.Fatal(err)
	}
	if _, err := receiveOne(oldRecv); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("old receive used reopened state: %v", err)
	}
	if _, _, err := bind.Open(0); !errors.Is(err, ErrBindAlreadyOpen) {
		t.Fatalf("duplicate Open: %v", err)
	}
	if err := bind.Send([][]byte{{1}}, nil); !errors.Is(err, ErrWrongEndpointType) {
		t.Fatalf("wrong endpoint: %v", err)
	}
}

func TestTCPFrameMaximumAndShortDestination(t *testing.T) {
	for _, capacity := range []int{MaxSegmentSize, MaxSegmentSize - 1} {
		a, b := net.Pipe()
		payload := bytes.Repeat([]byte{7}, MaxSegmentSize)
		go func() {
			defer b.Close()
			var header reqLen
			header.FromLen(len(payload))
			b.Write(header[:])
			b.Write(payload)
		}()
		buf := make([]byte, capacity)
		n, err := readTCPFrame(a, buf, time.Second, time.Second)
		a.Close()
		if capacity == MaxSegmentSize {
			if err != nil || n != MaxSegmentSize || !bytes.Equal(buf, payload) {
				t.Fatalf("maximum valid frame: n=%d err=%v", n, err)
			}
		} else if !errors.Is(err, errInvalidTCPFrame) {
			t.Fatalf("small destination buffer: %v", err)
		}
	}
}

func TestTCPRejectsInvalidSendBeforeDial(t *testing.T) {
	bind, _ := openTCPClient(t)
	for _, buf := range [][]byte{nil, make([]byte, MaxSegmentSize+1)} {
		if err := bind.Send([][]byte{buf}, nil); !errors.Is(err, errInvalidTCPFrame) {
			t.Fatalf("invalid outgoing frame: %v", err)
		}
	}
}

func TestTCPReplacingEndpointClosesDisplacedReader(t *testing.T) {
	bind, _ := openTCPClient(t)
	ln := loopbackTCP(t)
	pair := func() (*net.TCPConn, *net.TCPConn) {
		client, err := net.DialTCP("tcp4", nil, ln.Addr().(*net.TCPAddr))
		if err != nil {
			t.Fatal(err)
		}
		server, err := ln.AcceptTCP()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { client.Close(); server.Close() })
		return client, server
	}
	first, firstPeer := pair()
	second, _ := pair()
	ep, _ := bind.ParseEndpoint(ln.Addr().String())
	state := bind.state
	for _, conn := range []*net.TCPConn{first, second} {
		state.mu.Lock()
		err := bind.register(state, &tcpConnection{conn: conn, endpoint: ep.(*StdNetEndpoint)})
		state.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	}
	firstPeer.SetReadDeadline(time.Now().Add(time.Second))
	var buf [1]byte
	if _, err := firstPeer.Read(buf[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("displaced socket still open: %v", err)
	}
	done := make(chan struct{})
	go func() { bind.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close waits for an untracked reader")
	}
}
