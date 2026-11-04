package main

// SOCKS5 proxy backed by github.com/things-go/go-socks5. Outbound connections
// are dialed through the WireGuard userspace netstack (tnet), and hostnames are
// resolved inside the tunnel, so traffic never touches any system interface,
// route table or resolver. Authentication is optional: with credentials it
// requires username/password (RFC 1929); without, it accepts the no-auth method.

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	socks5 "github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// netstackResolver resolves hostnames inside the tunnel via the netstack DNS,
// so SOCKS5 requests for internal names work without touching the host resolver.
type netstackResolver struct {
	tnet *netstack.Net
	ctx  context.Context
}

func (r netstackResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	// Literal IPs need no DNS lookup. This also covers the 0.0.0.0 placeholder
	// that clients send as the source address in a UDP ASSOCIATE request.
	if ip := net.ParseIP(name); ip != nil {
		return ctx, ip, nil
	}
	// Some clients (e.g. PySocks) send "0" or "" as the UDP ASSOCIATE source
	// placeholder; the Go stdlib resolver maps "0" to 0.0.0.0, so mirror that
	// rather than failing the whole associate setup with "no such host".
	if name == "" || name == "0" {
		return ctx, net.IPv4zero, nil
	}
	lookupCtx := ctx
	if r.ctx != nil {
		lookupCtx = r.ctx
	}
	lookupCtx, cancel := context.WithTimeout(lookupCtx, 10*time.Second)
	defer cancel()
	addrs, err := r.tnet.LookupContextHost(lookupCtx, name)
	if err != nil {
		return ctx, nil, err
	}
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil {
			return ctx, ip, nil
		}
	}
	return ctx, nil, &net.DNSError{Err: "no addresses found", Name: name}
}

// socksLogger adapts device.Logger to the go-socks5 Logger interface.
type socksLogger struct {
	logger *device.Logger
}

func (l socksLogger) Errorf(format string, args ...interface{}) {
	l.logger.Errorf("socks5: "+format, args...)
}

// startSocks5 binds a SOCKS5 listener on the host and serves it in the
// background. When username is non-empty, username/password authentication is
// required (clients offering only no-auth are rejected).
func startSocks5(listen, username, password string, tnet *netstack.Net, logger *device.Logger) (*socksService, error) {
	if (username == "") != (password == "") {
		return nil, errors.New("SOCKS username and password must both be nonempty or both omitted")
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	if username == "" && !ln.Addr().(*net.TCPAddr).IP.IsLoopback() {
		ln.Close()
		return nil, errors.New("non-loopback SOCKS listeners require username and password")
	}

	serviceCtx, cancel := context.WithCancel(context.Background())
	service := &socksService{listener: ln, conns: make(map[net.Conn]struct{}), cancel: cancel}
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		stop := context.AfterFunc(serviceCtx, cancel)
		defer stop()
		target, err := tnet.DialContext(dialCtx, network, addr)
		if err != nil {
			return nil, err
		}
		return service.trackTarget(target)
	}
	opts := []socks5.Option{
		socks5.WithResolver(netstackResolver{tnet: tnet, ctx: serviceCtx}),
		socks5.WithConnectMiddleware(finishSocksHandshake),
		socks5.WithAssociateMiddleware(finishSocksHandshake),
		socks5.WithAssociateMiddleware(bindUDPAssociation),
		socks5.WithDial(dial),
		socks5.WithAssociateHandle(udpAssociateHandler(dial)),
		socks5.WithLogger(socksLogger{logger: logger}),
	}
	if username != "" {
		// go-socks5 enables UserPassAuthenticator only (no no-auth fallback)
		// once credentials are set, so unauthenticated clients are rejected.
		opts = append(opts, socks5.WithCredential(socks5.StaticCredentials{
			username: password,
		}))
		logger.Verbosef("socks5: username/password authentication enabled")
	}

	service.wg.Add(1)
	go service.serve(socks5.NewServer(opts...), logger)
	return service, nil
}

// A bounded handshake deadline is removed only after authentication and request
// parsing. Established streams and UDP associations may remain idle.
func finishSocksHandshake(_ context.Context, writer io.Writer, _ *socks5.Request) error {
	if conn, ok := writer.(net.Conn); ok {
		return conn.SetDeadline(time.Time{})
	}
	return errors.New("SOCKS request writer is not a connection")
}

const socksMaxConnections = 128
const socksMaxTargets = 128

var errSocksTargetLimit = errors.New("SOCKS target connection limit reached")

type socksService struct {
	listener net.Listener
	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	targets  map[*socksTarget]struct{}
	closed   bool
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

func (s *socksService) serve(server *socks5.Server, logger *device.Logger) {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				logger.Errorf("socks5: listener stopped: %v", err)
			}
			return
		}
		s.mu.Lock()
		if s.closed || len(s.conns) >= socksMaxConnections {
			s.mu.Unlock()
			conn.Close()
			continue
		}
		s.conns[conn] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		go func() {
			defer s.wg.Done()
			defer func() {
				conn.Close()
				s.mu.Lock()
				delete(s.conns, conn)
				s.mu.Unlock()
			}()
			if err := server.ServeConn(conn); err != nil {
				logger.Verbosef("socks5: connection ended: %v", err)
			}
		}()
	}
}

// Track established target sockets as well as host-side clients. Cancelling a
// dial context does not close a connection after DialContext has returned.
type socksTarget struct {
	net.Conn
	service  *socksService
	once     sync.Once
	closeErr error
}

func (s *socksService) trackTarget(conn net.Conn) (net.Conn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		conn.Close()
		return nil, net.ErrClosed
	}
	if len(s.targets) >= socksMaxTargets {
		conn.Close()
		return nil, errSocksTargetLimit
	}
	if s.targets == nil {
		s.targets = make(map[*socksTarget]struct{})
	}
	target := &socksTarget{Conn: conn, service: s}
	s.targets[target] = struct{}{}
	return target, nil
}

func (c *socksTarget) Close() error {
	c.once.Do(func() {
		c.closeErr = c.Conn.Close()
		c.service.mu.Lock()
		delete(c.service.targets, c)
		c.service.mu.Unlock()
	})
	return c.closeErr
}

// Preserve TCP half-close semantics used by the upstream proxy loop.
func (c *socksTarget) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return nil
}

func (s *socksService) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.closed = true
	s.cancel()
	s.listener.Close()
	conns := make([]net.Conn, 0, len(s.conns)+len(s.targets))
	for conn := range s.conns {
		conns = append(conns, conn)
	}
	for target := range s.targets {
		conns = append(conns, target)
	}
	s.mu.Unlock()
	// Close outside the lock: target.Close removes itself from the registry.
	for _, conn := range conns {
		conn.Close()
	}
	s.wg.Wait()
}

// bindUDPAssociation runs only after SOCKS authentication. A wildcard source
// port cannot be safely learned from the first datagram: another local user
// can win that race even when both clients share the loopback IP address.
// Clients must bind their UDP socket first and announce its port on TCP.
func bindUDPAssociation(_ context.Context, writer io.Writer, request *socks5.Request) error {
	peer, ok := request.RemoteAddr.(*net.TCPAddr)
	dest := request.DestAddr
	if !ok || peer == nil || peer.IP == nil || dest == nil || dest.Port <= 0 || dest.Port > 65535 ||
		(!dest.IP.IsUnspecified() && !dest.IP.Equal(peer.IP)) {
		if err := socks5.SendReply(writer, statute.RepRuleFailure, nil); err != nil {
			return err
		}
		return errors.New("UDP ASSOCIATE requires the TCP peer IP and an explicit nonzero client UDP source port")
	}
	bound := *dest
	bound.IP = append(net.IP(nil), peer.IP...)
	bound.FQDN = ""
	request.DestAddr = &bound
	return nil
}
