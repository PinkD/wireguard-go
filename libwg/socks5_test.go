package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	socks5 "github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
	"golang.zx2c4.com/wireguard/device"
)

func TestUDPAssociationSourceBinding(t *testing.T) {
	for _, tc := range []struct {
		name string
		ip   net.IP
		port int
		ok   bool
	}{
		{"explicitPeer", net.IPv4(127, 0, 0, 1), 1234, true},
		{"unspecifiedIP", net.IPv4zero, 1234, true},
		{"wildcardPort", net.IPv4zero, 0, false},
		{"wrongIP", net.IPv4(127, 0, 0, 2), 1234, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := &socks5.Request{
				RemoteAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4321},
				DestAddr:   &statute.AddrSpec{IP: tc.ip, Port: tc.port},
			}
			var reply bytes.Buffer
			err := bindUDPAssociation(context.Background(), &reply, req)
			if (err == nil) != tc.ok {
				t.Fatalf("allowed=%v, err=%v", tc.ok, err)
			}
			if tc.ok && (!req.DestAddr.IP.Equal(net.IPv4(127, 0, 0, 1)) || req.DestAddr.Port != tc.port) {
				t.Fatal("UDP source not pinned to TCP peer and announced port")
			}
			if !tc.ok && (reply.Len() < 2 || reply.Bytes()[1] != statute.RepRuleFailure) {
				t.Fatal("rejected association did not send rule failure")
			}
		})
	}
}

func listenTestUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// An authenticated association must not forward a different local process's
// packet, even if it arrives before the legitimate client's first datagram.
func TestAuthenticatedUDPRejectsOtherLoopbackSource(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	dialed := make(chan string, 4)
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed <- addr
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	server := socks5.NewServer(
		socks5.WithCredential(socks5.StaticCredentials{"user": "password"}),
		socks5.WithAssociateMiddleware(bindUDPAssociation),
		socks5.WithDial(dial),
		socks5.WithAssociateHandle(udpAssociateHandler(dial)),
	)

	serverDone := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		serverDone <- server.ServeConn(c)
	}()
	tcp, err := net.DialTimeout("tcp4", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	tcp.SetDeadline(time.Now().Add(3 * time.Second))
	tcp.Write([]byte{5, 1, 2})
	var auth [2]byte
	if _, err := io.ReadFull(tcp, auth[:]); err != nil || auth != [2]byte{5, 2} {
		t.Fatalf("auth negotiation: %v %v", auth, err)
	}
	tcp.Write(append(append([]byte{1, 4}, []byte("user")...), append([]byte{8}, []byte("password")...)...))
	if _, err := io.ReadFull(tcp, auth[:]); err != nil || auth != [2]byte{1, 0} {
		t.Fatalf("authentication: %v %v", auth, err)
	}
	legit, attacker, target := listenTestUDP(t), listenTestUDP(t), listenTestUDP(t)
	port := legit.LocalAddr().(*net.UDPAddr).Port
	request := []byte{5, 3, 0, 1, 0, 0, 0, 0, byte(port >> 8), byte(port)}
	tcp.Write(request)
	var reply [10]byte
	if _, err := io.ReadFull(tcp, reply[:]); err != nil || reply[1] != 0 || reply[3] != 1 {
		t.Fatalf("associate: %v %v", reply, err)
	}
	relay := &net.UDPAddr{IP: net.IP(reply[4:8]), Port: int(binary.BigEndian.Uint16(reply[8:]))}
	targetPort := target.LocalAddr().(*net.UDPAddr).Port
	packet := []byte{0, 0, 0, 1, 127, 0, 0, 1, byte(targetPort >> 8), byte(targetPort), 42}
	attackPacket := append(append([]byte(nil), packet[:10]...), 99)
	if _, err := attacker.WriteToUDP(attackPacket, relay); err != nil {
		t.Fatal(err)
	}
	select {
	case <-dialed:
		t.Fatal("unauthenticated local source opened a tunnel connection")
	case <-time.After(100 * time.Millisecond):
	}
	fragment := append([]byte(nil), packet...)
	fragment[2] = 1
	legit.WriteToUDP(fragment, relay)
	select {
	case <-dialed:
		t.Fatal("unsupported fragmented datagram was forwarded")
	case <-time.After(50 * time.Millisecond):
	}
	if _, err := legit.WriteToUDP(packet, relay); err != nil {
		t.Fatal(err)
	}
	target.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 100)
	n, from, err := target.ReadFromUDP(buf)
	if err != nil || !bytes.Equal(buf[:n], []byte{42}) {
		t.Fatalf("legitimate UDP packet: %v %v", buf[:n], err)
	}
	target.WriteToUDP([]byte{24}, from)
	legit.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err = legit.ReadFromUDP(buf)
	if err != nil || !bytes.Equal(buf[:n], append(packet[:10], 24)) {
		t.Fatalf("legitimate UDP response: %v %v", buf[:n], err)
	}
	// Same IP, different port remains denied after the legitimate first packet.
	attacker.WriteToUDP(attackPacket, relay)
	target.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, _, err := target.ReadFromUDP(buf); err == nil {
		t.Fatal("unrelated source reused the established association")
	}
	tcp.Close()
	select {
	case err := <-serverDone:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("association did not stop after closing TCP")
	}
}

func TestSocksListenerPolicyAndClose(t *testing.T) {
	logger := device.NewLogger(device.LogLevelSilent, "test")
	for _, credentials := range [][2]string{{"user", ""}, {"", "password"}} {
		if _, err := startSocks5("127.0.0.1:0", credentials[0], credentials[1], nil, logger); err == nil {
			t.Fatal("accepted incomplete credentials")
		}
	}
	service, err := startSocks5("127.0.0.1:0", "user", "password", nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	c, err := net.DialTimeout("tcp4", service.listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	c.Write([]byte{5, 1, 0})
	var response [2]byte
	if _, err := io.ReadFull(c, response[:]); err != nil || response != [2]byte{5, 255} {
		t.Fatalf("no-auth was not rejected: %v %v", response, err)
	}
	idle, err := net.DialTimeout("tcp4", service.listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	service.Close()
	idle.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := idle.Read(response[:]); err == nil {
		t.Fatal("Close did not disconnect idle handshake")
	}
}

type blockedTarget struct {
	net.Conn
	reading, writing    chan struct{}
	readOnce, writeOnce sync.Once
}

func (c *blockedTarget) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
}
func (c *blockedTarget) Read(p []byte) (int, error) {
	c.readOnce.Do(func() { close(c.reading) })
	return c.Conn.Read(p)
}
func (c *blockedTarget) Write(p []byte) (int, error) {
	c.writeOnce.Do(func() { close(c.writing) })
	return c.Conn.Write(p)
}

func TestSocksCloseUnblocksTargetReadAndWrite(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, cancel := context.WithCancel(context.Background())
	service := &socksService{listener: ln, cancel: cancel, conns: make(map[net.Conn]struct{})}
	pipe, peer := net.Pipe()
	target := &blockedTarget{Conn: pipe, reading: make(chan struct{}), writing: make(chan struct{})}
	t.Cleanup(func() { peer.Close(); service.Close() })
	server := socks5.NewServer(socks5.WithDial(func(context.Context, string, string) (net.Conn, error) {
		return service.trackTarget(target)
	}))
	service.wg.Add(1)
	go service.serve(server, device.NewLogger(device.LogLevelSilent, "test"))
	client, err := net.DialTimeout("tcp4", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(time.Second))
	client.Write([]byte{5, 1, 0})
	var auth [2]byte
	if _, err := io.ReadFull(client, auth[:]); err != nil {
		t.Fatal(err)
	}
	client.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 80})
	var reply [10]byte
	if _, err := io.ReadFull(client, reply[:]); err != nil || reply[1] != 0 {
		t.Fatalf("CONNECT: %v %v", reply, err)
	}
	client.Write([]byte{1})
	for _, entered := range []chan struct{}{target.reading, target.writing} {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("proxy did not reach blocked target")
		}
	}
	done := make(chan struct{})
	go func() { service.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close waited forever for target I/O")
	}
	service.mu.Lock()
	remaining := len(service.targets)
	service.mu.Unlock()
	if remaining != 0 {
		t.Fatal("closed target retained")
	}
	late, latePeer := net.Pipe()
	defer latePeer.Close()
	if _, err := service.trackTarget(late); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("late dial after Close: %v", err)
	}
	latePeer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := latePeer.Read(auth[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("late target was not closed: %v", err)
	}
}

type failedAssociateReply struct {
	net.Conn
	relay *net.UDPAddr
}

func (c *failedAssociateReply) Write(p []byte) (int, error) {
	if len(p) == 10 && p[1] == 0 {
		c.relay = &net.UDPAddr{IP: append(net.IP(nil), p[4:8]...), Port: int(binary.BigEndian.Uint16(p[8:]))}
	}
	return 0, io.ErrClosedPipe
}

func TestUDPAssociateReplyFailureClosesListener(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	writer := &failedAssociateReply{Conn: a}
	req := &socks5.Request{
		LocalAddr:  &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)},
		RemoteAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4321},
		DestAddr:   &statute.AddrSpec{IP: net.IPv4zero, Port: 1234},
		Reader:     bytes.NewReader(nil),
	}
	err := udpAssociateHandler(nil)(context.Background(), writer, req)
	if !errors.Is(err, io.ErrClosedPipe) || writer.relay == nil {
		t.Fatalf("failed reply: %v", err)
	}
	// Rebinding the exact relay port proves the failure path released the FD.
	rebound, err := net.ListenUDP("udp4", writer.relay)
	if err != nil {
		t.Fatalf("failed reply leaked UDP listener: %v", err)
	}
	rebound.Close()
}

func TestSocksTargetLimitAndReuse(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, cancel := context.WithCancel(context.Background())
	service := &socksService{listener: ln, cancel: cancel}
	var peers []net.Conn
	t.Cleanup(func() {
		service.Close()
		for _, peer := range peers {
			peer.Close()
		}
	})
	var first net.Conn
	for i := 0; i < socksMaxTargets; i++ {
		a, b := net.Pipe()
		peers = append(peers, b)
		tracked, err := service.trackTarget(a)
		if err != nil {
			t.Fatal(err)
		}
		if first == nil {
			first = tracked
		}
	}
	a, b := net.Pipe()
	defer b.Close()
	if _, err := service.trackTarget(a); !errors.Is(err, errSocksTargetLimit) {
		t.Fatalf("target cap: %v", err)
	}
	b.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := b.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("refused target not closed: %v", err)
	}
	first.Close()
	a, b = net.Pipe()
	peers = append(peers, b)
	if _, err := service.trackTarget(a); err != nil {
		t.Fatalf("released slot unavailable: %v", err)
	}
}
