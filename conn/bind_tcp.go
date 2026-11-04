package conn

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"time"
)

var _ Bind = (*TcpBind)(nil)

// MaxSegmentSize matches the largest packet accepted by the device.
const MaxSegmentSize = 65535

const (
	tcpMaxConnections = 128
	tcpDialTimeout    = 10 * time.Second
	tcpFrameTimeout   = 10 * time.Second
	tcpIdleTimeout    = 2 * time.Minute
)

var errInvalidTCPFrame = errors.New("invalid TCP frame length")

// NewTCPBind permits incoming connections for applications acting as a server.
func NewTCPBind() Bind { return newTCPBind(false) }

// NewTCPClientBind only dials configured peer endpoints. Replies use the same
// full-duplex TCP connection; no inbound listening socket is needed by clients.
func NewTCPClientBind() Bind { return newTCPBind(true) }

func newTCPBind(clientOnly bool) *TcpBind {
	return &TcpBind{
		clientOnly: clientOnly,
		dataPool: sync.Pool{New: func() any {
			return &recvData{buff: make([]byte, MaxSegmentSize)}
		}},
	}
}

type TcpBind struct {
	mu         sync.Mutex
	state      *tcpBindState
	mark       uint32
	clientOnly bool
	dataPool   sync.Pool
}

// Every Open owns independent state. An old ReceiveFunc must stay closed even
// when the bind is reopened, and an old reader must never reach the new channel.
type tcpBindState struct {
	mu       sync.Mutex
	dialMu   sync.Mutex
	conns    map[string]*tcpConnection
	listener *net.TCPListener
	ctx      context.Context
	cancel   context.CancelFunc
	recv     chan *recvData
	wg       sync.WaitGroup
	mark     uint32
}

type tcpConnection struct {
	conn     *net.TCPConn
	endpoint *StdNetEndpoint
	writeMu  sync.Mutex // the header and body form one indivisible write
}

type reqLen [4]byte

func (l *reqLen) Len() uint32   { return binary.LittleEndian.Uint32(l[:]) }
func (l *reqLen) FromLen(n int) { binary.LittleEndian.PutUint32(l[:], uint32(n)) }

type recvData struct {
	buff     []byte
	size     int
	endpoint Endpoint
}

func (t *TcpBind) makeReceive(s *tcpBindState) ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []Endpoint) (int, error) {
		select {
		case <-s.ctx.Done():
			return 0, net.ErrClosed
		default:
		}
		if len(bufs) == 0 {
			return 0, nil
		}
		select {
		case <-s.ctx.Done():
			return 0, net.ErrClosed
		case data := <-s.recv:
			defer t.dataPool.Put(data)
			if s.ctx.Err() != nil {
				return 0, net.ErrClosed
			}
			if len(bufs[0]) < data.size || len(sizes) == 0 || len(eps) == 0 {
				return 0, io.ErrShortBuffer
			}
			sizes[0] = copy(bufs[0], data.buff[:data.size])
			eps[0] = data.endpoint
			return 1, nil
		}
	}
}

// readTCPFrame checks the unsigned wire length before converting it to int or
// slicing. The partial-header and body deadline bounds slow/incomplete frames.
func readTCPFrame(conn net.Conn, buff []byte, idleTimeout, frameTimeout time.Duration) (int, error) {
	var header reqLen
	if err := conn.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
		return 0, err
	}
	if _, err := io.ReadFull(conn, header[:1]); err != nil {
		return 0, err
	}
	if err := conn.SetReadDeadline(time.Now().Add(frameTimeout)); err != nil {
		return 0, err
	}
	if _, err := io.ReadFull(conn, header[1:]); err != nil {
		return 0, err
	}
	size := header.Len()
	if size == 0 || size > MaxSegmentSize || uint64(size) > uint64(len(buff)) {
		return 0, errInvalidTCPFrame
	}
	return io.ReadFull(conn, buff[:int(size)])
}

func (s *tcpBindState) remove(c *tcpConnection) {
	s.mu.Lock()
	if s.conns[c.endpoint.DstToString()] == c {
		delete(s.conns, c.endpoint.DstToString())
	}
	s.mu.Unlock()
	c.conn.Close()
}

// register is called with s.mu held, so Close cannot race a WaitGroup.Add.
func (t *TcpBind) register(s *tcpBindState, c *tcpConnection) error {
	if s.ctx.Err() != nil {
		return net.ErrClosed
	}
	key := c.endpoint.DstToString()
	old := s.conns[key]
	if old == nil && len(s.conns) >= tcpMaxConnections {
		return errors.New("TCP connection limit reached")
	}
	if s.mark != 0 {
		if err := setTCPMark(c.conn, s.mark); err != nil {
			return err
		}
	}
	if old != nil {
		// An incoming connection may race a pending outbound dial for the
		// same endpoint. Do not leave the displaced reader outside the map.
		old.conn.Close()
	}
	s.conns[key] = c
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer s.remove(c)
		for {
			data := t.dataPool.Get().(*recvData)
			n, err := readTCPFrame(c.conn, data.buff, tcpIdleTimeout, tcpFrameTimeout)
			if err != nil {
				t.dataPool.Put(data)
				return
			}
			data.size, data.endpoint = n, c.endpoint
			select {
			case <-s.ctx.Done():
				t.dataPool.Put(data)
				return
			case s.recv <- data:
				// The receiver owns this buffer until it has copied the payload.
			}
		}
	}()
	return nil
}

func (t *TcpBind) accept(s *tcpBindState) {
	defer s.wg.Done()
	for {
		conn, err := s.listener.AcceptTCP()
		if err != nil {
			return
		}
		endpoint := &StdNetEndpoint{AddrPort: conn.RemoteAddr().(*net.TCPAddr).AddrPort()}
		s.mu.Lock()
		err = t.register(s, &tcpConnection{conn: conn, endpoint: endpoint})
		s.mu.Unlock()
		if err != nil {
			conn.Close()
		}
	}
}

func (t *TcpBind) Open(port uint16) ([]ReceiveFunc, uint16, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.state != nil {
		return nil, 0, ErrBindAlreadyOpen
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &tcpBindState{ctx: ctx, cancel: cancel, recv: make(chan *recvData), conns: make(map[string]*tcpConnection), mark: t.mark}
	actualPort := uint16(0)
	if !t.clientOnly {
		var err error
		s.listener, err = net.ListenTCP("tcp", &net.TCPAddr{Port: int(port)})
		if err != nil {
			cancel()
			return nil, 0, err
		}
		actualPort = uint16(s.listener.Addr().(*net.TCPAddr).Port)
		s.wg.Add(1)
		go t.accept(s)
	}
	t.state = s
	return []ReceiveFunc{t.makeReceive(s)}, actualPort, nil
}

func (t *TcpBind) Close() error {
	t.mu.Lock()
	s := t.state
	if s == nil {
		t.mu.Unlock()
		return nil
	}
	s.mu.Lock()
	s.cancel() // interrupts pending dial, receive, and channel delivery
	if s.listener != nil {
		s.listener.Close()
	}
	for _, c := range s.conns {
		c.conn.Close()
	}
	s.mu.Unlock()
	t.state = nil
	t.mu.Unlock()
	s.wg.Wait()
	return nil
}

func (t *TcpBind) getConn(endpoint Endpoint) (*tcpBindState, *tcpConnection, error) {
	ep, ok := endpoint.(*StdNetEndpoint)
	if !ok || ep == nil || !ep.AddrPort.IsValid() || ep.Port() == 0 {
		return nil, nil, ErrWrongEndpointType
	}
	t.mu.Lock()
	s := t.state
	t.mu.Unlock()
	if s == nil {
		return nil, nil, net.ErrClosed
	}
	// Serialize connection creation to avoid duplicate sockets and leaked readers.
	s.dialMu.Lock()
	defer s.dialMu.Unlock()
	s.mu.Lock()
	if c := s.conns[ep.DstToString()]; c != nil {
		s.mu.Unlock()
		return s, c, nil
	}
	if s.ctx.Err() != nil {
		s.mu.Unlock()
		return nil, nil, net.ErrClosed
	}
	if len(s.conns) >= tcpMaxConnections {
		s.mu.Unlock()
		return nil, nil, errors.New("TCP connection limit reached")
	}
	s.mu.Unlock()
	dialer := net.Dialer{Timeout: tcpDialTimeout}
	conn, err := dialer.DialContext(s.ctx, "tcp", ep.DstToString())
	if err != nil {
		return nil, nil, err
	}
	c := &tcpConnection{conn: conn.(*net.TCPConn), endpoint: &StdNetEndpoint{AddrPort: ep.AddrPort}}
	s.mu.Lock()
	err = t.register(s, c)
	s.mu.Unlock()
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	return s, c, nil
}

func (t *TcpBind) Send(bufs [][]byte, endpoint Endpoint) error {
	for _, buf := range bufs {
		if len(buf) == 0 || len(buf) > MaxSegmentSize {
			return errInvalidTCPFrame
		}
	}
	s, c, err := t.getConn(endpoint)
	if err != nil {
		return err
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	for _, buf := range bufs {
		var header reqLen
		header.FromLen(len(buf))
		if err = c.conn.SetWriteDeadline(time.Now().Add(tcpFrameTimeout)); err == nil {
			buffers := net.Buffers{header[:], buf}
			_, err = buffers.WriteTo(c.conn)
		}
		if err != nil {
			s.remove(c)
			return err
		}
	}
	return nil
}

func (t *TcpBind) SetMark(mark uint32) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.mark = mark
	if s := t.state; s != nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.mark = mark
		for _, c := range s.conns {
			if err := setTCPMark(c.conn, mark); err != nil {
				return err
			}
		}
	}
	return nil
}

func (t *TcpBind) ParseEndpoint(s string) (Endpoint, error) {
	e, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &StdNetEndpoint{AddrPort: e}, nil
}

func (t *TcpBind) BatchSize() int {
	if runtime.GOOS == "linux" {
		return IdealBatchSize
	}
	return 1
}
