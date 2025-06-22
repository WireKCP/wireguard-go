/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"errors"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"syscall"

	"github.com/xtaci/kcp-go/v5"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	mtuLimit    = 1520 // Use 1520 to match kcp-go's default and avoid slice out of bounds
	max_UDP     = 65507
	dataLimit   = max_UDP - kcp.IKCP_OVERHEAD
	msgChanSize = 8192 // Increased further to reduce risk of drops under burst
)

type Msg struct {
	data   []byte
	length int
	addr   *net.UDPAddr
	closed bool
}

// StdNetBind implements Bind for all platforms. While Windows has its own Bind
// (see bind_windows.go), it may fall back to StdNetBind.
// TODO: Remove usage of ipv{4,6}.PacketConn when net.UDPConn has comparable
// methods for sending and receiving multiple datagrams per-syscall. See the
// proposal in https://github.com/golang/go/issues/45886#issuecomment-1218301564.
type KCPExtBind struct {
	mu             sync.Mutex
	ipv4           *net.UDPConn
	ipv6           *net.UDPConn
	v4listen       *kcp.Listener
	v6listen       *kcp.Listener
	msgChan        chan *Msg
	blackhole4     bool
	blackhole6     bool
	ipv6RxOffload  bool
	ipv6TxOffload  bool
	ipv4RxOffload  bool
	ipv4TxOffload  bool
	udpAddrPool    sync.Pool
	msgsPool       sync.Pool
	dataBufferPool sync.Pool
	sessions       sync.Map
}

func NewExtBindKCP() Bind {
	return &KCPExtBind{
		udpAddrPool: sync.Pool{
			New: func() any {
				return &net.UDPAddr{
					IP: make([]byte, 16),
				}
			},
		},
		msgChan: make(chan *Msg, msgChanSize),
		msgsPool: sync.Pool{
			New: func() any {
				msgs := make([]ipv6.Message, IdealBatchSize)
				for i := range msgs {
					msgs[i].Buffers = make(net.Buffers, 1)
					msgs[i].OOB = make([]byte, 0, stickyControlSize+gsoControlSize)
				}
				return &msgs
			},
		},
		dataBufferPool: sync.Pool{
			New: func() any {
				buf := make([]byte, dataLimit)
				return &buf
			},
		},
	}
}

func (*KCPExtBind) ParseEndpoint(s string) (Endpoint, error) {
	e, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &StdNetEndpoint{
		AddrPort: e,
	}, nil
}

func (bind *KCPExtBind) SetMark(mark uint32) error {
	return nil
}

func (bind *KCPExtBind) v4loop() {
	for {
		if conn, err := bind.v4listen.AcceptKCP(); err == nil {
			conn.SetWriteDelay(false)
			conn.SetNoDelay(1, 10, 2, 1) // interval=10ms
			conn.SetMtu(mtuLimit)
			conn.SetWindowSize(65535, 65535)
			conn.SetACKNoDelay(true)
			// --- Save session for recv ---
			addrStr := conn.RemoteAddr().String()
			if old, exists := bind.sessions.Load(addrStr); exists && old != nil {
				old.(*kcp.UDPSession).Close()
			}
			bind.sessions.Store(addrStr, conn)

			go bind.handleConn(conn)
		} else {
			bind.msgChan <- &Msg{
				closed: true,
				addr:   nil,
			}
			break
		}
	}
}

func (bind *KCPExtBind) v6loop() {
	for {
		if conn, err := bind.v6listen.AcceptKCP(); err == nil {
			conn.SetWriteDelay(false)
			conn.SetNoDelay(1, 10, 2, 1)
			conn.SetMtu(mtuLimit)
			conn.SetWindowSize(65535, 65535)
			conn.SetACKNoDelay(true)
			// --- Save session for recv ---
			addrStr := conn.RemoteAddr().String()
			if old, exists := bind.sessions.Load(addrStr); exists && old != nil {
				old.(*kcp.UDPSession).Close()
			}
			bind.sessions.Store(addrStr, conn)

			go bind.handleConn(conn)
		} else {
			bind.msgChan <- &Msg{
				closed: true,
				addr:   nil,
			}
			break
		}
	}
}

func (bind *KCPExtBind) handleConn(conn *kcp.UDPSession) {
	if conn == nil {
		return
	}
	defer func() {
		addrStr := conn.RemoteAddr().String()
		bind.sessions.Delete(addrStr)
		conn.Close()
	}()
	for {
		bufPtr := bind.dataBufferPool.Get().(*[]byte)
		n, err := conn.Read(*bufPtr)
		if err != nil {
			bind.dataBufferPool.Put(bufPtr)
			return
		}
		if n > 0 {
			msgBuf := make([]byte, n)
			copy(msgBuf, (*bufPtr)[:n])
			msg := &Msg{
				data:   msgBuf,
				length: n,
				addr:   conn.RemoteAddr().(*net.UDPAddr),
			}
			select {
			case bind.msgChan <- msg:
			default:
			}
		}
		bind.dataBufferPool.Put(bufPtr)
	}
}

func (s *KCPExtBind) Open(uport uint16) ([]ReceiveFunc, uint16, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var err error
	var tries int

	if s.ipv4 != nil || s.ipv6 != nil {
		return nil, 0, ErrBindAlreadyOpen
	}
again:
	port := int(uport)
	var v4conn, v6conn *net.UDPConn

	v4conn, port, err = listenNet("udp4", port)
	if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
		return nil, 0, err
	}
	// Listen on the same port as we're using for ipv4.
	v6conn, port, err = listenNet("udp6", port)
	if uport == 0 && errors.Is(err, syscall.EADDRINUSE) && tries < 100 {
		v4conn.Close()
		tries++
		goto again
	}
	if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
		v4conn.Close()
		return nil, 0, err
	}

	s.v4listen, err = kcp.ServeConn(nil, 10, 3, v4conn)
	if err != nil {
		return nil, 0, err
	}

	s.v6listen, err = kcp.ServeConn(nil, 10, 3, v6conn)
	if err != nil {
		s.v4listen.Close()
		return nil, 0, err
	}

	go s.v4loop()
	go s.v6loop()

	var fns []ReceiveFunc
	if v4conn != nil {
		fns = append(fns, s.makeReceiveIPv4(v4conn))
		s.ipv4 = v4conn
	}
	if v6conn != nil {
		fns = append(fns, s.makeReceiveIPv6(v6conn))

		s.ipv6 = v6conn
	}
	if len(fns) == 0 {
		return nil, 0, syscall.EAFNOSUPPORT
	}

	return fns, uint16(port), nil
}

func (s *KCPExtBind) putMessages(msgs *[]ipv6.Message) {
	for i := range *msgs {
		(*msgs)[i].OOB = (*msgs)[i].OOB[:0]
		(*msgs)[i] = ipv6.Message{Buffers: (*msgs)[i].Buffers, OOB: (*msgs)[i].OOB}
	}
	s.msgsPool.Put(msgs)
}

func (s *KCPExtBind) getMessages() *[]ipv6.Message {
	return s.msgsPool.Get().(*[]ipv6.Message)
}

var (
	// If compilation fails here these are no longer the same underlying type.
	_ ipv6.Message = ipv4.Message{}
)

func (s *KCPExtBind) receiveIP(
	conn *net.UDPConn,
	bufs [][]byte,
	sizes []int,
	eps []Endpoint,
) (n int, err error) {
	msgs := s.getMessages()
	for i := range bufs {
		(*msgs)[i].Buffers[0] = bufs[i]
		(*msgs)[i].OOB = (*msgs)[i].OOB[:cap((*msgs)[i].OOB)]
	}
	defer s.putMessages(msgs)
	var numMsgs int = 0
	recv := <-s.msgChan
	msg := &(*msgs)[numMsgs]

	if recv.closed {
		for len(s.msgChan) > 0 {
			<-s.msgChan
		}
		return 0, net.ErrClosed
	}

	msg.Addr = recv.addr
	copy(msg.Buffers[0], recv.data)
	msg.N = recv.length
	msg.NN = 0

	sizes[numMsgs] = recv.length
	if sizes[numMsgs] == 0 {
		return numMsgs, nil
	}
	addrPort := msg.Addr.(*net.UDPAddr).AddrPort()
	ep := &StdNetEndpoint{AddrPort: addrPort} // TODO: remove allocation
	getSrcFromControl(msg.OOB[:msg.NN], ep)
	eps[numMsgs] = ep
	numMsgs++
	return numMsgs, nil
}

func (s *KCPExtBind) makeReceiveIPv4(conn *net.UDPConn) ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []Endpoint) (n int, err error) {
		return s.receiveIP(conn, bufs, sizes, eps)
	}
}

func (s *KCPExtBind) makeReceiveIPv6(conn *net.UDPConn) ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []Endpoint) (n int, err error) {
		return s.receiveIP(conn, bufs, sizes, eps)
	}
}

// TODO: When all Binds handle IdealBatchSize, remove this dynamic function and
// rename the IdealBatchSize constant to BatchSize.
func (s *KCPExtBind) BatchSize() int {
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		return IdealBatchSize
	}
	return 1
}

func (s *KCPExtBind) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var err1, err2 error

	if s.v4listen != nil {
		err1 = s.v4listen.Close()
		s.v4listen = nil
	}
	if s.v6listen != nil {
		err2 = s.v6listen.Close()
		s.v6listen = nil
	}
	if s.ipv4 != nil {
		err1 = s.ipv4.Close()
		s.ipv4 = nil
	}
	if s.ipv6 != nil {
		err2 = s.ipv6.Close()
		s.ipv6 = nil
	}
	s.blackhole4 = false
	s.blackhole6 = false
	s.ipv4TxOffload = false
	s.ipv4RxOffload = false
	s.ipv6TxOffload = false
	s.ipv6RxOffload = false

	s.sessions.Range(func(key, value any) bool {
		if sess, ok := value.(*kcp.UDPSession); ok {
			sess.Close()
		}
		return true
	})

	s.sessions.Clear()

	if err1 != nil {
		return err1
	}
	return err2
}

func (s *KCPExtBind) Send(bufs [][]byte, endpoint Endpoint) error {
	s.mu.Lock()
	blackhole := s.blackhole4
	conn := s.ipv4
	offload := s.ipv4TxOffload
	is6 := false
	if endpoint.DstIP().Is6() {
		blackhole = s.blackhole6
		conn = s.ipv6
		is6 = true
		offload = s.ipv6TxOffload
	}
	s.mu.Unlock()

	if blackhole {
		return nil
	}
	if conn == nil {
		return syscall.EAFNOSUPPORT
	}

	msgs := s.getMessages()
	defer s.putMessages(msgs)
	ua := s.udpAddrPool.Get().(*net.UDPAddr)
	defer s.udpAddrPool.Put(ua)
	if is6 {
		as16 := endpoint.DstIP().As16()
		copy(ua.IP, as16[:])
		ua.IP = ua.IP[:16]
	} else {
		as4 := endpoint.DstIP().As4()
		copy(ua.IP, as4[:])
		ua.IP = ua.IP[:4]
	}
	ua.Port = int(endpoint.(*StdNetEndpoint).Port())
	var (
		retried bool
		err     error
	)
retry:
	if offload {
		n := coalesceMessages(ua, endpoint.(*StdNetEndpoint), bufs, *msgs, setGSOSize)
		err = s.send(conn, (*msgs)[:n])
		if err != nil && offload && errShouldDisableUDPGSO(err) {
			offload = false
			s.mu.Lock()
			if is6 {
				s.ipv6TxOffload = false
			} else {
				s.ipv4TxOffload = false
			}
			s.mu.Unlock()
			retried = true
			goto retry
		}
	} else {
		for i := range bufs {
			(*msgs)[i].Addr = ua
			(*msgs)[i].Buffers[0] = bufs[i]
			setSrcControl(&(*msgs)[i].OOB, endpoint.(*StdNetEndpoint))
		}
		err = s.send(conn, (*msgs)[:len(bufs)])
	}
	if retried {
		return ErrUDPGSODisabled{onLaddr: conn.LocalAddr().String(), RetryErr: err}
	}
	return err
}

func (s *KCPExtBind) send(conn *net.UDPConn, msgs []ipv6.Message) error {
	var (
		sess *kcp.UDPSession
		err  error
	)
	for _, msg := range msgs {
		addrStr := msg.Addr.String()
		if val, ok := s.sessions.Load(addrStr); ok {
			sess = val.(*kcp.UDPSession)
		} else {
			sess, err = kcp.NewConn2(msg.Addr, nil, 10, 3, conn)
			if err == nil {
				sess.SetWriteDelay(false)
				sess.SetNoDelay(1, 10, 2, 1)
				sess.SetMtu(mtuLimit)
				sess.SetWindowSize(4096, 4096)
				sess.SetACKNoDelay(true)
				s.sessions.Store(addrStr, sess)
			}
		}
		if sess != nil && err == nil {
			_, err = sess.Write(msg.Buffers[0])
		}
	}
	return err
}
