/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/xtaci/kcp-go/v5"
)

const (
	kcpSessionMTU       = 1400
	kcpMaxPacket        = 65535
	kcpUpdateInterval   = 10 * time.Millisecond
	kcpPeerSwitchWindow = 5 * time.Second
	kcpSocketBufferSize = 4 * 1024 * 1024
)

type KCPOptions struct {
	Profile string
}

type kcpTuning struct {
	window     int
	congestion int
}

func (options KCPOptions) tuning() (kcpTuning, error) {
	switch options.Profile {
	case "", "lan":
		return kcpTuning{window: 1024, congestion: 1}, nil
	case "wan":
		return kcpTuning{window: 512, congestion: 0}, nil
	default:
		return kcpTuning{}, errors.New("KCP profile must be lan or wan")
	}
}

type kcpSession struct {
	conn         *net.UDPConn
	remote       *net.UDPAddr
	kcp          *kcp.KCP
	mu           sync.Mutex
	lastActivity time.Time
	writeErr     error
	retired      bool
}

type kcpPeer struct {
	address          string
	remote           *net.UDPAddr
	sessions         map[uint32]*kcpSession
	tx               *kcpSession
	preferred        *kcpSession
	lastInbound      time.Time
	lastConversation time.Time
}

type kcpBindState struct {
	mu      sync.Mutex
	closed  bool
	done    chan struct{}
	peers   map[string]*kcpPeer
	updater sync.WaitGroup
	options KCPOptions
}

type KCPExtBind struct {
	mu         sync.Mutex
	ipv4       *net.UDPConn
	ipv6       *net.UDPConn
	state      *kcpBindState
	blackhole4 bool
	blackhole6 bool
	options    KCPOptions
}

func NewExtBindKCP() Bind { return &KCPExtBind{} }

func NewExtBindKCPWithOptions(options KCPOptions) (*KCPExtBind, error) {
	if _, err := options.tuning(); err != nil {
		return nil, err
	}
	return &KCPExtBind{options: options}, nil
}

func (*KCPExtBind) ParseEndpoint(address string) (Endpoint, error) {
	endpoint, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, err
	}
	return &StdNetEndpoint{AddrPort: endpoint}, nil
}

func (*KCPExtBind) SetMark(mark uint32) error { return nil }

func newKCPSession(conn *net.UDPConn, remote *net.UDPAddr, conv uint32, options KCPOptions) (*kcpSession, error) {
	tuning, err := options.tuning()
	if err != nil {
		return nil, err
	}
	remoteCopy := *remote
	remoteCopy.IP = append(net.IP(nil), remote.IP...)
	session := &kcpSession{
		conn:         conn,
		remote:       &remoteCopy,
		lastActivity: time.Now(),
	}
	session.kcp = kcp.NewKCP(conv, func(packet []byte, size int) {
		if size < 0 || size > len(packet) {
			session.writeErr = errors.New("KCP produced an invalid datagram size")
			return
		}
		_, err := conn.WriteToUDP(packet[:size], session.remote)
		if err != nil {
			session.writeErr = err
		}
	})
	if session.kcp.SetMtu(kcpSessionMTU) != 0 {
		return nil, errors.New("KCP rejected session MTU")
	}
	session.kcp.NoDelay(1, 10, 2, tuning.congestion)
	session.kcp.WndSize(tuning.window, tuning.window)
	return session, nil
}

func (session *kcpSession) takeWriteError() error {
	err := session.writeErr
	session.writeErr = nil
	return err
}

func (state *kcpBindState) updateLoop() {
	defer state.updater.Done()
	ticker := time.NewTicker(kcpUpdateInterval)
	defer ticker.Stop()
	for {
		select {
		case <-state.done:
			return
		case <-ticker.C:
			state.mu.Lock()
			var sessions []*kcpSession
			for _, peer := range state.peers {
				for _, session := range peer.sessions {
					sessions = append(sessions, session)
				}
			}
			state.mu.Unlock()
			for _, session := range sessions {
				session.mu.Lock()
				if !session.retired {
					session.kcp.Update()
					session.takeWriteError()
				}
				session.mu.Unlock()
			}
		}
	}
}

func (state *kcpBindState) newPeerLocked(remote *net.UDPAddr) *kcpPeer {
	address := remote.String()
	peer := state.peers[address]
	if peer == nil {
		remoteCopy := *remote
		remoteCopy.IP = append(net.IP(nil), remote.IP...)
		peer = &kcpPeer{
			address:  address,
			remote:   &remoteCopy,
			sessions: make(map[uint32]*kcpSession),
		}
		state.peers[address] = peer
	}
	return peer
}

func (state *kcpBindState) newSessionLocked(peer *kcpPeer, conn *net.UDPConn, conv uint32) (*kcpSession, error) {
	if session := peer.sessions[conv]; session != nil {
		return session, nil
	}
	session, err := newKCPSession(conn, peer.remote, conv, state.options)
	if err != nil {
		return nil, err
	}
	peer.sessions[conv] = session
	return session, nil
}

func (state *kcpBindState) retireSessionsLocked(peer *kcpPeer, keep *kcpSession) {
	for conv, session := range peer.sessions {
		if session == keep {
			continue
		}
		session.mu.Lock()
		session.retired = true
		session.kcp.ReleaseTX()
		session.mu.Unlock()
		delete(peer.sessions, conv)
	}
	if peer.tx != keep {
		peer.tx = nil
	}
	if peer.preferred != keep {
		peer.preferred = nil
	}
}

func (state *kcpBindState) newOutboundSessionLocked(peer *kcpPeer, conn *net.UDPConn) (*kcpSession, error) {
	for {
		var convBytes [4]byte
		if _, err := rand.Read(convBytes[:]); err != nil {
			return nil, err
		}
		conv := binary.LittleEndian.Uint32(convBytes[:])
		if peer.sessions[conv] != nil {
			continue
		}
		session, err := state.newSessionLocked(peer, conn, conv)
		if err != nil {
			return nil, err
		}
		peer.tx, peer.preferred = session, session
		peer.lastConversation = time.Now()
		return session, nil
	}
}

func (state *kcpBindState) outboundSession(conn *net.UDPConn, remote *net.UDPAddr) (*kcpPeer, *kcpSession, error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closed {
		return nil, nil, net.ErrClosed
	}
	peer := state.newPeerLocked(remote)
	active := peer.preferred
	if active == nil {
		active = peer.tx
	}
	if active != nil && time.Since(peer.lastInbound) <= kcpPeerSwitchWindow ||
		active != nil && time.Since(peer.lastConversation) <= kcpPeerSwitchWindow {
		return peer, active, nil
	}
	state.retireSessionsLocked(peer, nil)
	session, err := state.newOutboundSessionLocked(peer, conn)
	return peer, session, err
}

func kcpPacketHasPush(packet []byte) bool {
	for offset := 0; offset+kcp.IKCP_OVERHEAD <= len(packet); {
		command := packet[offset+4]
		length := uint64(binary.LittleEndian.Uint32(packet[offset+20 : offset+24]))
		if length > uint64(len(packet)-offset-kcp.IKCP_OVERHEAD) {
			return false
		}
		if command == 81 {
			return true
		}
		offset += kcp.IKCP_OVERHEAD + int(length)
	}
	return false
}

func (state *kcpBindState) inboundSession(conn *net.UDPConn, remote *net.UDPAddr, packet []byte) (*kcpPeer, *kcpSession, bool) {
	if len(packet) < kcp.IKCP_OVERHEAD {
		return nil, nil, false
	}
	conv := GetConv(packet)
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closed {
		return nil, nil, false
	}
	peer := state.newPeerLocked(remote)
	session := peer.sessions[conv]
	created := false
	if session == nil {
		if !kcpPacketHasPush(packet) {
			return nil, nil, false
		}
		var err error
		session, err = state.newSessionLocked(peer, conn, conv)
		if err != nil {
			return nil, nil, false
		}
		created = true
	}
	return peer, session, created
}

func (state *kcpBindState) noteInbound(peer *kcpPeer, session *kcpSession, created, startsConversation bool, now time.Time) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closed || state.peers[peer.address] != peer {
		return
	}
	session.mu.Lock()
	retired := session.retired
	session.mu.Unlock()
	if retired {
		return
	}
	if created && startsConversation && (peer.preferred == nil || now.Sub(peer.lastInbound) > kcpPeerSwitchWindow) {
		state.retireSessionsLocked(peer, session)
		peer.preferred = session
		peer.lastConversation = now
	}
	peer.lastInbound = now
}

func kcpPacketStartsConversation(packet []byte) bool {
	return len(packet) >= kcp.IKCP_OVERHEAD && packet[4] == 81 && binary.LittleEndian.Uint32(packet[12:16]) == 0
}

func (state *kcpBindState) readySessions(conn *net.UDPConn) []*kcpSession {
	state.mu.Lock()
	defer state.mu.Unlock()
	var sessions []*kcpSession
	for _, peer := range state.peers {
		for _, session := range peer.sessions {
			if session.conn == conn {
				sessions = append(sessions, session)
			}
		}
	}
	return sessions
}

func (state *kcpBindState) drainReady(conn *net.UDPConn, bufs [][]byte, sizes []int, endpoints []Endpoint) (int, error) {
	count := 0
	for _, session := range state.readySessions(conn) {
		for count < len(bufs) {
			session.mu.Lock()
			if session.retired {
				session.mu.Unlock()
				break
			}
			packetSize := session.kcp.PeekSize()
			if packetSize <= 0 {
				err := session.takeWriteError()
				session.mu.Unlock()
				if err != nil {
					return count, err
				}
				break
			}
			if packetSize > len(bufs[count]) {
				session.mu.Unlock()
				if count > 0 {
					return count, nil
				}
				return 0, io.ErrShortBuffer
			}
			packetSize = session.kcp.Recv(bufs[count])
			err := session.takeWriteError()
			if packetSize > 0 {
				sizes[count] = packetSize
				endpoints[count] = &StdNetEndpoint{AddrPort: session.remote.AddrPort()}
				session.lastActivity = time.Now()
				count++
			}
			session.mu.Unlock()
			if err != nil {
				return count, err
			}
		}
		if count == len(bufs) {
			break
		}
	}
	return count, nil
}

func (state *kcpBindState) receive(conn *net.UDPConn, readBuffer []byte, bufs [][]byte, sizes []int, endpoints []Endpoint) (int, error) {
	if len(bufs) == 0 || len(sizes) < len(bufs) || len(endpoints) < len(bufs) {
		return 0, errors.New("invalid WireGuard receive buffers")
	}
	for {
		select {
		case <-state.done:
			return 0, net.ErrClosed
		default:
		}
		if count, err := state.drainReady(conn, bufs, sizes, endpoints); count > 0 || err != nil {
			return count, err
		}
		length, remote, err := conn.ReadFromUDP(readBuffer)
		if err != nil {
			select {
			case <-state.done:
				return 0, net.ErrClosed
			default:
				return 0, err
			}
		}
		packet := readBuffer[:length]
		peer, session, created := state.inboundSession(conn, remote, packet)
		if session == nil {
			continue
		}
		now := time.Now()
		session.mu.Lock()
		if session.retired {
			session.mu.Unlock()
			continue
		}
		inputErr := session.kcp.Input(packet, true, false)
		if inputErr == 0 {
			session.lastActivity = now
		}
		writeErr := session.takeWriteError()
		session.mu.Unlock()
		if inputErr == 0 {
			state.noteInbound(peer, session, created, kcpPacketStartsConversation(packet), now)
		}
		if writeErr != nil {
			return 0, writeErr
		}
	}
}

func (state *kcpBindState) receiveFunc(conn *net.UDPConn) ReceiveFunc {
	var readMu sync.Mutex
	readBuffer := make([]byte, kcpMaxPacket)
	return func(bufs [][]byte, sizes []int, endpoints []Endpoint) (int, error) {
		readMu.Lock()
		defer readMu.Unlock()
		return state.receive(conn, readBuffer, bufs, sizes, endpoints)
	}
}

func (bind *KCPExtBind) Open(port uint16) ([]ReceiveFunc, uint16, error) {
	bind.mu.Lock()
	defer bind.mu.Unlock()
	if bind.state != nil {
		return nil, 0, ErrBindAlreadyOpen
	}
	var ipv4conn, ipv6conn *net.UDPConn
	var actualPort int
	var err error
	for attempt := 0; ; attempt++ {
		ipv4conn, actualPort, err = listenNet("udp4", int(port))
		if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
			return nil, 0, err
		}
		ipv6conn, actualPort, err = listenNet("udp6", actualPort)
		if port == 0 && errors.Is(err, syscall.EADDRINUSE) && attempt < 100 {
			if ipv4conn != nil {
				ipv4conn.Close()
			}
			continue
		}
		if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
			if ipv4conn != nil {
				ipv4conn.Close()
			}
			return nil, 0, err
		}
		break
	}
	if ipv4conn == nil && ipv6conn == nil {
		return nil, 0, syscall.EAFNOSUPPORT
	}
	for _, socket := range []*net.UDPConn{ipv4conn, ipv6conn} {
		if socket == nil {
			continue
		}
		bufferErr := errors.Join(disableKCPGRO(socket), socket.SetReadBuffer(kcpSocketBufferSize), socket.SetWriteBuffer(kcpSocketBufferSize))
		if bufferErr != nil {
			if ipv4conn != nil {
				ipv4conn.Close()
			}
			if ipv6conn != nil {
				ipv6conn.Close()
			}
			return nil, 0, bufferErr
		}
	}
	state := &kcpBindState{done: make(chan struct{}), peers: make(map[string]*kcpPeer), options: bind.options}
	bind.ipv4, bind.ipv6, bind.state = ipv4conn, ipv6conn, state
	var receives []ReceiveFunc
	if ipv4conn != nil {
		receives = append(receives, state.receiveFunc(ipv4conn))
	}
	if ipv6conn != nil {
		receives = append(receives, state.receiveFunc(ipv6conn))
	}
	state.updater.Add(1)
	go state.updateLoop()
	return receives, uint16(actualPort), nil
}

func (*KCPExtBind) BatchSize() int { return 1 }

func (bind *KCPExtBind) Close() error {
	bind.mu.Lock()
	state := bind.state
	if state == nil {
		bind.mu.Unlock()
		return nil
	}
	state.mu.Lock()
	state.closed = true
	close(state.done)
	state.mu.Unlock()
	ipv4conn, ipv6conn := bind.ipv4, bind.ipv6
	bind.ipv4, bind.ipv6, bind.state = nil, nil, nil
	bind.blackhole4, bind.blackhole6 = false, false
	bind.mu.Unlock()
	var closeErrors []error
	if ipv4conn != nil {
		closeErrors = append(closeErrors, ipv4conn.Close())
	}
	if ipv6conn != nil {
		closeErrors = append(closeErrors, ipv6conn.Close())
	}
	state.updater.Wait()
	return errors.Join(closeErrors...)
}

func (bind *KCPExtBind) Send(packets [][]byte, endpoint Endpoint) error {
	bind.mu.Lock()
	state, ipv4conn, ipv6conn := bind.state, bind.ipv4, bind.ipv6
	blackhole := bind.blackhole4
	conn := ipv4conn
	if endpoint.DstIP().Is6() {
		blackhole = bind.blackhole6
		conn = ipv6conn
	}
	bind.mu.Unlock()
	if state == nil {
		return net.ErrClosed
	}
	if blackhole {
		return nil
	}
	if conn == nil {
		return syscall.EAFNOSUPPORT
	}
	stdEndpoint, ok := endpoint.(*StdNetEndpoint)
	if !ok {
		return errors.New("unsupported KCP endpoint type")
	}
	remote := net.UDPAddrFromAddrPort(stdEndpoint.AddrPort)
	for {
		_, session, err := state.outboundSession(conn, remote)
		if err != nil {
			return err
		}
		session.mu.Lock()
		if session.retired {
			session.mu.Unlock()
			continue
		}
		tuning, _ := state.options.tuning()
		if session.kcp.WaitSnd() >= 2*tuning.window {
			session.mu.Unlock()
			timer := time.NewTimer(kcpUpdateInterval)
			select {
			case <-state.done:
				timer.Stop()
				return net.ErrClosed
			case <-timer.C:
				continue
			}
		}
		select {
		case <-state.done:
			session.mu.Unlock()
			return net.ErrClosed
		default:
		}
		for _, packet := range packets {
			if len(packet) == 0 || len(packet) > kcpMaxPacket {
				session.mu.Unlock()
				return errors.New("invalid KCP packet length")
			}
			if session.kcp.Send(packet) != 0 {
				session.mu.Unlock()
				return errors.New("KCP rejected packet")
			}
		}
		session.lastActivity = time.Now()
		session.kcp.Update()
		err = session.takeWriteError()
		session.mu.Unlock()
		return err
	}
}
