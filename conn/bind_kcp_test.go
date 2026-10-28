package conn

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/xtaci/kcp-go/v5"
)

func TestKCPBindReceiveFuncAfterClose(t *testing.T) {
	bind := NewDefaultBindKCP().(*KCPBind)
	fns, _, err := bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	bind.Close()
	bufs := make([][]byte, 1)
	bufs[0] = make([]byte, 1)
	sizes := make([]int, 1)
	eps := make([]Endpoint, 1)
	for _, fn := range fns {
		fn(bufs, sizes, eps)
	}
}

func TestKCPExtBindLifecycle(t *testing.T) {
	bind := NewExtBindKCP().(*KCPExtBind)
	t.Cleanup(func() { bind.Close() })
	var previous ReceiveFunc
	for iteration := 0; iteration < 20; iteration++ {
		functions, _, err := bind.Open(0)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := bind.Open(0); !errors.Is(err, ErrBindAlreadyOpen) {
			t.Fatalf("second Open: %v", err)
		}
		if previous != nil {
			if _, err := previous([][]byte{make([]byte, 1500)}, make([]int, 1), make([]Endpoint, 1)); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("old receiver: %v", err)
			}
		}
		finished := make(chan error, 2)
		for worker := 0; worker < 2; worker++ {
			go func() {
				_, err := functions[0]([][]byte{make([]byte, 1500)}, make([]int, 1), make([]Endpoint, 1))
				finished <- err
			}()
		}
		if err := bind.Close(); err != nil {
			t.Fatal(err)
		}
		for worker := 0; worker < 2; worker++ {
			select {
			case err := <-finished:
				if !errors.Is(err, net.ErrClosed) {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("receiver blocked after Close")
			}
		}
		previous = functions[0]
	}
}

type kcpTestClient struct {
	conn   *net.UDPConn
	remote *net.UDPAddr
	state  *kcp.KCP
}

func newKCPTestClient(t *testing.T, address string, conv uint32) *kcpTestClient {
	t.Helper()
	remote, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	client := &kcpTestClient{conn: conn, remote: remote}
	client.state = kcp.NewKCP(conv, func(packet []byte, size int) {
		conn.WriteToUDP(packet[:size], remote)
	})
	if client.state.SetMtu(kcpSessionMTU) != 0 {
		t.Fatal("client rejected KCP MTU")
	}
	client.state.NoDelay(1, 10, 2, 1)
	client.state.WndSize(4096, 4096)
	t.Cleanup(func() { conn.Close() })
	return client
}

func (client *kcpTestClient) send(packet []byte) error {
	if client.state.Send(packet) != 0 {
		return errors.New("test client KCP rejected packet")
	}
	client.state.Update()
	return nil
}

func (client *kcpTestClient) receive(buffer []byte) (int, error) {
	if err := client.conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return 0, err
	}
	packet := make([]byte, kcpSessionMTU)
	for {
		if size := client.state.PeekSize(); size > 0 {
			return client.state.Recv(buffer), nil
		}
		length, _, err := client.conn.ReadFromUDP(packet)
		if err != nil {
			return 0, err
		}
		client.state.Input(packet[:length], true, true)
	}
}

func TestKCPExtBindConversationRoutingAndPacketBoundaries(t *testing.T) {
	bind := NewExtBindKCP().(*KCPExtBind)
	functions, port, err := bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { bind.Close() })
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
	clients := []*kcpTestClient{newKCPTestClient(t, address, 11), newKCPTestClient(t, address, 22)}
	expected := [][]byte{bytes.Repeat([]byte{0x42}, 1452), bytes.Repeat([]byte{0x24}, 768)}
	for index, client := range clients {
		if err := client.send(expected[index]); err != nil {
			t.Fatal(err)
		}
	}
	seen := make([]bool, len(clients))
	for range clients {
		buffer, sizes, endpoints := make([]byte, 65535), make([]int, 1), make([]Endpoint, 1)
		if _, err := functions[0]([][]byte{buffer}, sizes, endpoints); err != nil {
			t.Fatal(err)
		}
		index := -1
		for candidate := range expected {
			if bytes.Equal(buffer[:sizes[0]], expected[candidate]) {
				index = candidate
				break
			}
		}
		if index < 0 || seen[index] {
			t.Fatalf("unexpected or duplicate packet, length %d", sizes[0])
		}
		seen[index] = true
		if err := bind.Send([][]byte{expected[index]}, endpoints[0]); err != nil {
			t.Fatal(err)
		}
	}
	for index, client := range clients {
		buffer := make([]byte, 65535)
		length, err := client.receive(buffer)
		if err != nil || !bytes.Equal(buffer[:length], expected[index]) {
			t.Fatalf("client %d response length %d: %v", index, length, err)
		}
	}
}

func TestKCPExtBindWireMTUAndNoFEC(t *testing.T) {
	remote, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	bind := NewExtBindKCP().(*KCPExtBind)
	if _, _, err := bind.Open(0); err != nil {
		t.Fatal(err)
	}
	defer bind.Close()
	endpoint, err := bind.ParseEndpoint(remote.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := bind.Send([][]byte{bytes.Repeat([]byte{0x42}, 1452)}, endpoint); err != nil {
		t.Fatal(err)
	}
	remote.SetReadDeadline(time.Now().Add(3 * time.Second))
	buffer := make([]byte, 2048)
	var total int
	for total < 2 {
		length, _, err := remote.ReadFromUDP(buffer)
		if err != nil {
			t.Fatal(err)
		}
		if length > kcpSessionMTU || length < kcp.IKCP_OVERHEAD {
			t.Fatalf("wire length %d", length)
		}
		if buffer[4] != 81 {
			t.Fatalf("expected raw KCP PUSH, got command %x", buffer[4])
		}
		total++
	}
}

func TestKCPExtBindRotatesConversationAfterSilence(t *testing.T) {
	remote, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	bind := NewExtBindKCP().(*KCPExtBind)
	if _, _, err := bind.Open(0); err != nil {
		t.Fatal(err)
	}
	defer bind.Close()
	endpoint, err := bind.ParseEndpoint(remote.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := bind.Send([][]byte{[]byte("first")}, endpoint); err != nil {
		t.Fatal(err)
	}
	if err := remote.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, kcpSessionMTU)
	length, _, err := remote.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	oldConv := GetConv(buffer[:length])
	peerKey := remote.LocalAddr().String()
	bind.state.mu.Lock()
	peer := bind.state.peers[peerKey]
	peer.lastConversation = time.Now().Add(-2 * kcpPeerSwitchWindow)
	peer.lastInbound = time.Time{}
	bind.state.mu.Unlock()
	if err := bind.Send([][]byte{[]byte("second")}, endpoint); err != nil {
		t.Fatal(err)
	}
	for {
		length, _, err = remote.ReadFromUDP(buffer)
		if err != nil {
			t.Fatal(err)
		}
		if GetConv(buffer[:length]) == oldConv {
			continue
		}
		if sequence := binary.LittleEndian.Uint32(buffer[12:16]); sequence != 0 {
			t.Fatalf("new conversation started at sequence %d", sequence)
		}
		return
	}
}

func TestKCPProfiles(t *testing.T) {
	for _, profile := range []string{"", "lan", "wan"} {
		bind, err := NewExtBindKCPWithOptions(KCPOptions{Profile: profile})
		if err != nil {
			t.Fatal(err)
		}
		tuning, err := bind.options.tuning()
		if err != nil || tuning.window == 0 {
			t.Fatalf("profile %q: %+v, %v", profile, tuning, err)
		}
		if profile == "wan" && tuning.congestion != 0 {
			t.Fatal("WAN congestion control disabled")
		}
	}
	if _, err := NewExtBindKCPWithOptions(KCPOptions{Profile: "invalid"}); err == nil {
		t.Fatal("accepted unknown profile")
	}
}

func TestKCPBackpressureCanceledByClose(t *testing.T) {
	bind := NewExtBindKCP().(*KCPExtBind)
	if _, _, err := bind.Open(0); err != nil {
		t.Fatal(err)
	}
	defer bind.Close()
	remote := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	peer, session, err := bind.state.outboundSession(bind.ipv4, remote)
	if err != nil {
		t.Fatal(err)
	}
	bind.state.mu.Lock()
	peer.lastInbound = time.Now().Add(time.Hour)
	bind.state.mu.Unlock()
	tuning, _ := bind.state.options.tuning()
	session.mu.Lock()
	for packet := 0; packet < 2*tuning.window; packet++ {
		session.kcp.Send([]byte{1})
	}
	session.mu.Unlock()
	endpoint, _ := bind.ParseEndpoint(remote.String())
	finished := make(chan error, 1)
	go func() { finished <- bind.Send([][]byte{{1}}, endpoint) }()
	select {
	case err := <-finished:
		t.Fatalf("saturated sender did not block: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	if err := bind.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-finished:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not release saturated sender")
	}
}

func TestKCPHybridWireAndReceive(t *testing.T) {
	remote, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	bind, err := NewExtBindKCPWithOptions(KCPOptions{Profile: "lan", UnreliableData: true})
	if err != nil {
		t.Fatal(err)
	}
	functions, port, err := bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer bind.Close()
	if _, rxOffload := supportsUDPOffload(bind.ipv4); rxOffload {
		t.Fatal("KCP socket enables GRO without a coalesced-datagram reader")
	}
	endpoint, err := bind.ParseEndpoint(remote.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 1452)
	binary.LittleEndian.PutUint32(data, 4)
	control := make([]byte, 148)
	binary.LittleEndian.PutUint32(control, 1)
	if err := bind.Send([][]byte{control, data}, endpoint); err != nil {
		t.Fatal(err)
	}
	remote.SetReadDeadline(time.Now().Add(3 * time.Second))
	buffer := make([]byte, 2048)
	seenData, seenControl := false, false
	for !seenData || !seenControl {
		length, _, err := remote.ReadFromUDP(buffer)
		if err != nil {
			t.Fatal(err)
		}
		switch buffer[0] {
		case kcpDataMarker:
			if !bytes.Equal(buffer[1:length], data) {
				t.Fatal("hybrid data changed")
			}
			seenData = true
		case kcpReliableMarker:
			if length < 25 || buffer[5] != 81 || binary.LittleEndian.Uint32(buffer[25:29]) != 1 {
				t.Fatal("handshake not carried by KCP")
			}
			seenControl = true
		default:
			t.Fatal("unrecognized hybrid marker")
		}
	}
	destination := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)}
	for _, malformed := range [][]byte{{}, {2, 4}, append([]byte{kcpDataMarker}, control...), {kcpDataMarker, 4}} {
		if _, err := remote.WriteToUDP(malformed, destination); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := remote.WriteToUDP(append([]byte{kcpDataMarker}, data...), destination); err != nil {
		t.Fatal(err)
	}
	bind.ipv4.SetReadDeadline(time.Now().Add(3 * time.Second))
	sizes, endpoints := make([]int, 1), make([]Endpoint, 1)
	count, err := functions[0]([][]byte{buffer}, sizes, endpoints)
	if err != nil || count != 1 || !bytes.Equal(buffer[:sizes[0]], data) {
		t.Fatalf("hybrid receive count=%d, error=%v", count, err)
	}
	if endpoints[0].DstToString() != remote.LocalAddr().String() {
		t.Fatal("hybrid endpoint changed")
	}
}

func TestKCPProfilesRecoverLossAndReordering(t *testing.T) {
	for _, profile := range []string{"lan", "wan"} {
		t.Run(profile, func(t *testing.T) {
			tuning, _ := (KCPOptions{Profile: profile}).tuning()
			var forward, reverse [][]byte
			dropped, transmissions := 0, 0
			sender := kcp.NewKCP(123, func(packet []byte, size int) {
				transmissions++
				if transmissions%7 == 1 {
					dropped++
					return
				}
				forward = append(forward, bytes.Clone(packet[:size]))
			})
			receiver := kcp.NewKCP(123, func(packet []byte, size int) {
				reverse = append(reverse, bytes.Clone(packet[:size]))
			})
			for _, protocol := range []*kcp.KCP{sender, receiver} {
				protocol.SetMtu(kcpSessionMTU)
				protocol.NoDelay(1, 10, 2, tuning.congestion)
				protocol.WndSize(tuning.window, tuning.window)
			}
			defer sender.ReleaseTX()
			defer receiver.ReleaseTX()
			const packetCount = 64
			for sequence := 0; sequence < packetCount; sequence++ {
				packet := bytes.Repeat([]byte{byte(sequence)}, 1452)
				if sender.Send(packet) != 0 {
					t.Fatal("KCP rejected message")
				}
			}
			ticker := time.NewTicker(kcpUpdateInterval)
			defer ticker.Stop()
			deadline := time.NewTimer(10 * time.Second)
			defer deadline.Stop()
			received := 0
			buffer := make([]byte, 1452)
			for received < packetCount || sender.WaitSnd() != 0 {
				select {
				case <-deadline.C:
					t.Fatalf("delivered %d/%d, pending %d", received, packetCount, sender.WaitSnd())
				case <-ticker.C:
				}
				sender.Update()
				receiver.Update()
				packets := forward
				forward = nil
				for index := len(packets) - 1; index >= 0; index-- {
					receiver.Input(packets[index], true, false)
					receiver.Input(packets[index], true, false)
				}
				packets = reverse
				reverse = nil
				for _, packet := range packets {
					sender.Input(packet, true, false)
				}
				for receiver.PeekSize() > 0 {
					length := receiver.Recv(buffer)
					if received >= packetCount || length != len(buffer) || !bytes.Equal(buffer, bytes.Repeat([]byte{byte(received)}, len(buffer))) {
						t.Fatalf("corrupted or duplicated message %d", received)
					}
					received++
				}
			}
			if dropped == 0 {
				t.Fatal("loss injection did not run")
			}
			t.Logf("delivered %d intact ordered messages; dropped %d datagrams, reversed and duplicated deliveries", received, dropped)
		})
	}
}
