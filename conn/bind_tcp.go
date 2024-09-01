package conn

import (
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync"

	"golang.zx2c4.com/wireguard/common"
)

var (
	_ Bind = (*TcpBind)(nil)
)

// MaxSegmentSize ref: device.MaxSegmentSize, we choose the max
const MaxSegmentSize = 65535

func NewTCPBind() Bind {
	return &TcpBind{
		dataPool: sync.Pool{
			New: func() any {
				data := &recvData{
					buff: make([]byte, MaxSegmentSize),
				}
				return data
			},
		},
	}
}

type TcpBind struct {
	// TODO: do we need mutex?
	tcpConnMap common.SyncMap[string, *net.TCPConn]
	listener   *net.TCPListener

	dataPool  sync.Pool
	recvChan  chan *recvData
	closeChan chan struct{}
}

type reqLen [4]byte

func (l *reqLen) Len() int {
	return int(l[0]) + int(l[1])<<8 + int(l[2])<<16 + int(l[3])<<24
}

func (l *reqLen) FromLen(len int) {
	l[0] = byte(len & 0xff)
	l[1] = byte(len >> 8 & 0xff)
	l[2] = byte(len >> 16 & 0xff)
	l[3] = byte(len >> 24 & 0xff)
}

type recvData struct {
	len      [4]byte
	buff     []byte
	size     int
	endpoint Endpoint
}

func (t *TcpBind) makeReceive() ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []Endpoint) (n int, err error) {
		if len(bufs) == 0 {
			return 0, nil
		}

		count := 0
		for {
			select {
			case <-t.closeChan:
				return 0, net.ErrClosed
			case data := <-t.recvChan:
				if data == nil {
					continue
				}
				sizes[count] = data.size
				copy(bufs[count], data.buff[:sizes[count]])
				eps[count] = data.endpoint
				count++
				if count == len(bufs) {
					return count, nil
				}
			default:
				return count, nil
			}
		}
	}
}

func (t *TcpBind) handleConn(conn *net.TCPConn, endpoint Endpoint) {
	go func() {
		data := t.dataPool.Get().(*recvData)
		defer t.dataPool.Put(data)
		defer conn.Close()
		for {
			// read uint32 size header
			_, err := io.ReadFull(conn, data.len[:])
			if err != nil {
				return
			}
			l := reqLen(data.len)
			size := l.Len()
			// read real data
			n, err := io.ReadFull(conn, data.buff[:size])
			if err != nil {
				return
			}
			if n != size {
				continue
			}
			data.size = size
			data.endpoint = endpoint
			select {
			case <-t.closeChan:
				return
			default:
			}
			t.recvChan <- data
		}
	}()
}

func (t *TcpBind) accept() {
	for {
		conn, err := t.listener.AcceptTCP()
		if err != nil {
			return
		}
		addrPort := conn.RemoteAddr().(*net.TCPAddr).AddrPort()
		endpoint := &StdNetEndpoint{AddrPort: addrPort}
		t.tcpConnMap.Store(endpoint.DstToString(), conn)
		t.handleConn(conn, endpoint)
	}
}

func (t *TcpBind) Open(port uint16) (fns []ReceiveFunc, actualPort uint16, err error) {
	t.recvChan = make(chan *recvData)
	t.closeChan = make(chan struct{})

	t.listener, err = net.ListenTCP("tcp", &net.TCPAddr{Port: int(port)})
	if err != nil {
		return nil, 0, err
	}
	go t.accept()
	fn := t.makeReceive()
	return []ReceiveFunc{fn}, port, nil
}

func (t *TcpBind) Close() error {
	var err error
	t.tcpConnMap.Range(func(endpoint string, v *net.TCPConn) bool {
		e := v.Close()
		if e != nil {
			err = e
		}
		return true
	})
	if t.listener != nil {
		_ = t.listener.Close()
	}
	if t.closeChan != nil {
		close(t.closeChan)
	}
	return err
}

func (t *TcpBind) getConn(endpoint Endpoint) (*net.TCPConn, error) {
	conn, ok := t.tcpConnMap.Load(endpoint.DstToString())
	if ok {
		return conn, nil
	}

	ip := make(net.IP, net.IPv6len)
	if endpoint.DstIP().Is6() {
		as16 := endpoint.DstIP().As16()
		copy(ip, as16[:])
	} else {
		as4 := endpoint.DstIP().As4()
		copy(ip, as4[:])
		ip = ip[:4]
	}
	addr := &net.TCPAddr{
		IP:   ip,
		Port: int(endpoint.(*StdNetEndpoint).Port()),
	}
	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		return nil, err
	}
	t.handleConn(conn, endpoint)
	t.tcpConnMap.Store(endpoint.DstToString(), conn)
	return conn, nil
}

func (t *TcpBind) Send(bufs [][]byte, endpoint Endpoint) error {
	conn, err := t.getConn(endpoint)
	if err != nil {
		return err
	}
	for _, buf := range bufs {
		var l reqLen
		l.FromLen(len(buf))
		_, err := conn.Write(l[:])
		if err != nil {
			return err
		}
		_, err = conn.Write(buf)
		if err != nil {
			return err
		}
	}
	return nil
}

func (t *TcpBind) ParseEndpoint(s string) (Endpoint, error) {
	e, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &StdNetEndpoint{
		AddrPort: e,
	}, nil
}

func (t *TcpBind) BatchSize() int {
	if runtime.GOOS == "linux" {
		return IdealBatchSize
	}
	return 1
}
