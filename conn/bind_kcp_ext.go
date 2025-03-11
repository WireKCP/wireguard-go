/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"errors"
	"fmt"
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
	mtuLimit = 1500
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
	mu   sync.Mutex // protects all fields except as specified
	RWmu sync.RWMutex
	ipv4 *net.UDPConn
	ipv6 *net.UDPConn

	pcv4 *ipv4.PacketConn
	pcv6 *ipv6.PacketConn

	connKCPs map[string]*kcp.UDPSession

	chRec chan Msg

	ipv4TxOffload bool
	ipv4RxOffload bool
	ipv6TxOffload bool
	ipv6RxOffload bool

	// these two fields are not guarded by mu
	udpAddrPool sync.Pool
	msgsPool    sync.Pool
	// a system-wide packet buffer shared among sending, receiving and FEC
	// to mitigate high-frequency memory allocation for packets, bytes from xmitBuf
	// is aligned to 64bit

	blackhole4 bool
	blackhole6 bool
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
		chRec: make(chan Msg),
		msgsPool: sync.Pool{
			New: func() any {
				// ipv6.Message and ipv4.Message are interchangeable as they are
				// both aliases for x/net/internal/socket.Message.
				msgs := make([]ipv6.Message, IdealBatchSize)
				for i := range msgs {
					msgs[i].Buffers = make(net.Buffers, 1)
					msgs[i].OOB = make([]byte, 0, stickyControlSize+gsoControlSize)
				}
				return &msgs
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

func (s *KCPExtBind) Open(uport uint16) ([]ReceiveFunc, uint16, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var err error
	var tries int

	if s.ipv4 != nil || s.ipv6 != nil {
		return nil, 0, ErrBindAlreadyOpen
	}

	s.connKCPs = make(map[string]*kcp.UDPSession)

	// Attempt to open ipv4 and ipv6 listeners on the same port.
	// If uport is 0, we can retry on failure.
again:
	port := int(uport)
	var v4conn, v6conn *net.UDPConn
	var v4pc *ipv4.PacketConn
	var v6pc *ipv6.PacketConn

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

	var fns []ReceiveFunc
	if v4conn != nil {
		s.ipv4TxOffload, s.ipv4RxOffload = supportsUDPOffload(v4conn)
		if runtime.GOOS == "linux" || runtime.GOOS == "android" {
			v4pc = ipv4.NewPacketConn(v4conn)
			s.pcv4 = v4pc
		}
		fns = append(fns, s.makeReceiveIPv4(v4pc, v4conn, s.ipv4RxOffload))
		s.ipv4 = v4conn
	}
	if v6conn != nil {
		s.ipv6TxOffload, s.ipv6RxOffload = supportsUDPOffload(v6conn)
		if runtime.GOOS == "linux" || runtime.GOOS == "android" {
			v6pc = ipv6.NewPacketConn(v6conn)
			s.pcv6 = v6pc
		}
		fns = append(fns, s.makeReceiveIPv6(v6pc, v6conn, s.ipv6RxOffload))
		s.ipv6 = v6conn
	}
	if len(fns) == 0 {
		return nil, 0, syscall.EAFNOSUPPORT
	}

	go func() {
		listener, err := kcp.ServeConn(nil, 10, 3, v4conn)
		if err != nil {
			return
		}
		for {
			conn, err := listener.AcceptKCP()
			if err != nil {
				s.chRec <- Msg{closed: true}
				return
			}
			if s.ipv4 == nil {
				s.chRec <- Msg{closed: true}
				return
			}
			s.RWmu.Lock()
			s.connKCPs[conn.RemoteAddr().String()] = conn
			s.RWmu.Unlock()
			go func(conn *kcp.UDPSession) {
				for {
					if s.ipv4 == nil {
						return
					}
					msg := Msg{data: make([]byte, mtuLimit)}
					msg.length, err = conn.Read(msg.data)
					if err != nil {
						println("Read error")
						return
					}
					msg.addr = conn.RemoteAddr().(*net.UDPAddr)
					s.chRec <- msg
				}
			}(conn)
		}
	}()

	go func() {
		listenerv6, err := kcp.ServeConn(nil, 10, 3, v6conn)
		if err != nil {
			return
		}
		for {
			conn, err := listenerv6.AcceptKCP()
			if err != nil {
				s.chRec <- Msg{closed: true}
				return
			}
			if s.ipv6 == nil {
				s.chRec <- Msg{closed: true}
				return
			}
			s.RWmu.Lock()
			s.connKCPs[conn.RemoteAddr().String()] = conn
			s.RWmu.Unlock()
			go func(conn *kcp.UDPSession) {
				for {
					if s.ipv6 == nil {
						return
					}
					msg := Msg{data: make([]byte, mtuLimit)}
					msg.length, err = conn.Read(msg.data)
					if err != nil {
						println("Read error")
						return
					}
					msg.addr = conn.RemoteAddr().(*net.UDPAddr)
					s.chRec <- msg
				}
			}(conn)
		}
	}()

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
	br batchReader,
	conn *net.UDPConn,
	rxOffload bool,
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
	//var numMsgs int
	// if runtime.GOOS == "linux" || runtime.GOOS == "android" {
	// 	if rxOffload {
	// 		readAt := len(*msgs) - (IdealBatchSize / udpSegmentMaxDatagrams)
	// 		numMsgs, err = br.ReadBatch((*msgs)[readAt:], 0)
	// 		if err != nil {
	// 			return 0, err
	// 		}
	// 		numMsgs, err = splitCoalescedMessages(*msgs, readAt, getGSOSize)
	// 		if err != nil {
	// 			return 0, err
	// 		}
	// 	} else {
	// 		numMsgs, err = br.ReadBatch(*msgs, 0)
	// 		if err != nil {
	// 			return 0, err
	// 		}
	// 	}
	// } else {
	//msg := &(*msgs)[0]
	//msg.N, msg.NN, _, msg.Addr, err = conn.ReadMsgUDP(msg.Buffers[0], msg.OOB)
	//if err != nil {
	//	return 0, err
	//}
	//numMsgs = 1
	// }
	for recvMsg := range s.chRec {
		if recvMsg.closed {
			return 0, net.ErrClosed
		}
		msg := &(*msgs)[0]
		msg.N = recvMsg.length
		msg.NN = 0
		copy(msg.Buffers[0], recvMsg.data)
		if msg.N > 0 {
			fmt.Printf("Data : %x\n", msg.Buffers[0][:msg.N])
			fmt.Printf("Length : %d\n", msg.N)
		}
		sizes[0] = msg.N
		addrPort := recvMsg.addr
		ep := &StdNetEndpoint{AddrPort: addrPort.AddrPort()} // TODO: remove allocation
		getSrcFromControl(msg.OOB[:msg.NN], ep)
		eps[0] = ep
		return 1, nil
	}
	return 0, nil
}

func (s *KCPExtBind) makeReceiveIPv4(pc *ipv4.PacketConn, conn *net.UDPConn, rxOffload bool) ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []Endpoint) (n int, err error) {
		return s.receiveIP(pc, conn, rxOffload, bufs, sizes, eps)
	}
}

func (s *KCPExtBind) makeReceiveIPv6(pc *ipv6.PacketConn, conn *net.UDPConn, rxOffload bool) ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []Endpoint) (n int, err error) {
		return s.receiveIP(pc, conn, rxOffload, bufs, sizes, eps)
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
	if s.connKCPs != nil {
		for k := range s.connKCPs {
			delete(s.connKCPs, k)
		}
		s.connKCPs = nil
	}
	if s.ipv4 != nil {
		err1 = s.ipv4.Close()
		s.ipv4 = nil
		s.pcv4 = nil
	}
	if s.ipv6 != nil {
		err2 = s.ipv6.Close()
		s.ipv6 = nil
		s.pcv6 = nil
	}
	s.blackhole4 = false
	s.blackhole6 = false
	s.ipv4TxOffload = false
	s.ipv4RxOffload = false
	s.ipv6TxOffload = false
	s.ipv6RxOffload = false
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
		err error
	)
	for _, msg := range msgs {
		s.RWmu.RLock()
		kcpsession, exists := s.connKCPs[msg.Addr.String()]
		s.RWmu.RUnlock()
		println("Send and RUnlock")
		if !exists {
			udpaddr := msg.Addr.(*net.UDPAddr)
			fmt.Printf("Send to %s\n", udpaddr.String())
			sess, err := kcp.NewConn(udpaddr.String(), nil, 10, 3, conn)
			if err != nil {
				err = syscall.EAFNOSUPPORT
			}
			if s.connKCPs != nil {
				s.RWmu.Lock()
				s.connKCPs[msg.Addr.String()] = sess
				s.RWmu.Unlock()
				println("Send and Unlock")
			}
			sess.Write(msg.Buffers[0])
		} else {
			kcpsession.Write(msg.Buffers[0])
		}
		fmt.Printf("Data : %x\n", msg.Buffers[0])
	}
	return err
}
