package libprobe

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	protocolICMP     = 1  // Internet Control Message
	protocolIPv6ICMP = 58 // ICMP for IPv6
	KindICMP         = "ICMP"
)

// IcmpID manages unique ICMP Echo identifiers for concurrent probes
type IcmpID struct {
	counter uint32
}

// Get returns a unique ICMP Echo identifier
func (c *IcmpID) Get() uint16 {
	return uint16(atomic.AddUint32(&c.counter, 1) % 65535)
}

// ICMPExtention defines ICMP-specific probe parameters
type ICMPExtention struct {
	TTL      int    // Time To Live value
	SourceIP string // Source IP address for the probe
	EnableV6 bool   // Whether to use IPv6
	Sequence int    // ICMP sequence number
	Size     int    // ICMP packet size
}

type ICMPResult struct {
	BaseResult[ICMPExtention]
	Address  string
	Sequence int
	Size     int
}

func (r ICMPResult) RTT() time.Duration {
	return r.Duration
}

func (r ICMPResult) String() string {
	if !r.Success {
		return "ICMP probe failed"
	}
	return fmt.Sprintf("RTT: %v, Address: %s", r.Duration, r.Address)
}

type ICMPProber struct {
	icmpID *IcmpID
}

func NewICMPProber() *ICMPProber {
	return &ICMPProber{
		icmpID: &IcmpID{},
	}
}

func (p *ICMPProber) Kind() string {
	return KindICMP
}

func (p *ICMPProber) Probe(target Target[ICMPExtention]) (Result[ICMPExtention], error) {
	r := &ICMPResult{
		BaseResult: BaseResult[ICMPExtention]{
			Target: target,
		},
		Sequence: target.Extention.Sequence,
		Size:     target.Extention.Size,
	}

	ip := net.ParseIP(target.Address)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", target.Address)
	}
	isIPv6 := ip.To4() == nil && target.Extention.EnableV6

	localAddr := target.Extention.SourceIP
	if localAddr == "" {
		if isIPv6 {
			localAddr = "::"
		} else {
			localAddr = "0.0.0.0"
		}
	}

	ttl := 64 // 默认 TTL
	if target.Extention.TTL > 0 {
		ttl = target.Extention.TTL
	}

	seq := 1 // 默认序列号
	if target.Extention.Sequence > 0 {
		seq = target.Extention.Sequence
	}

	hop, err := p.sendICMP(target.Address, localAddr, ttl,
		int(p.icmpID.Get()), target.Timeout, seq, isIPv6)
	if err != nil {
		return nil, err
	}

	r.Success = hop.Success
	r.Duration = hop.Elapsed
	r.Address = hop.Addr

	return r, nil
}

func (p *ICMPProber) sendICMP(destAddr string, srcAddr string, ttl int,
	echoID int, timeout time.Duration, seq int, ipv6 bool) (hop struct {
	Success bool
	Elapsed time.Duration
	Addr    string
}, err error) {

	if ipv6 {
		return p.icmpIPv6(srcAddr, &net.IPAddr{IP: net.ParseIP(destAddr)},
			ttl, echoID, timeout, seq)
	}
	return p.icmpIPv4(srcAddr, &net.IPAddr{IP: net.ParseIP(destAddr)},
		ttl, echoID, timeout, seq)
}

func (p *ICMPProber) icmpIPv4(localAddr string, dst net.Addr, ttl int, echoID int, timeout time.Duration, seq int) (hop struct {
	Success bool
	Elapsed time.Duration
	Addr    string
}, err error) {
	hop.Success = false
	start := time.Now()
	c, err := icmp.ListenPacket("ip4:icmp", localAddr)
	if err != nil {
		return hop, err
	}
	defer c.Close()

	if err = c.IPv4PacketConn().SetTTL(ttl); err != nil {
		return hop, err
	}

	if err = c.SetDeadline(time.Now().Add(timeout)); err != nil {
		return hop, err
	}

	bs := make([]byte, 4)
	binary.LittleEndian.PutUint32(bs, uint32(seq))
	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   echoID,
			Seq:  seq,
			Data: append(bs, 'x'),
		},
	}

	wb, err := wm.Marshal(nil)
	if err != nil {
		return hop, err
	}

	if _, err := c.WriteTo(wb, dst); err != nil {
		return hop, err
	}

	peer, _, err := p.listenForSpecific4(c, append(bs, 'x'), echoID, seq, wb)
	if err != nil {
		return hop, err
	}

	hop.Elapsed = time.Since(start)
	hop.Addr = peer
	hop.Success = true
	return hop, err
}

func (p *ICMPProber) icmpIPv6(localAddr string, dst net.Addr, ttl, echoID int, timeout time.Duration, seq int) (hop struct {
	Success bool
	Elapsed time.Duration
	Addr    string
}, err error) {
	hop.Success = false
	start := time.Now()
	c, err := icmp.ListenPacket("ip6:ipv6-icmp", localAddr)
	if err != nil {
		return hop, err
	}

	defer c.Close()

	if err = c.IPv6PacketConn().SetHopLimit(ttl); err != nil {
		return hop, err
	}

	if err = c.SetDeadline(time.Now().Add(timeout)); err != nil {
		return hop, err
	}

	bs := make([]byte, 4)
	binary.LittleEndian.PutUint32(bs, uint32(seq))
	wm := icmp.Message{
		Type: ipv6.ICMPTypeEchoRequest,
		Code: 0,
		Body: &icmp.Echo{
			ID:   echoID,
			Seq:  seq,
			Data: append(bs, 'x'),
		},
	}
	wb, err := wm.Marshal(nil)
	if err != nil {
		return hop, err
	}

	if _, err := c.WriteTo(wb, dst); err != nil {
		return hop, err
	}

	peer, _, err := p.listenForSpecific6(c, append(bs, 'x'), echoID, seq)
	if err != nil {
		return hop, err
	}

	hop.Elapsed = time.Since(start)
	hop.Addr = peer
	hop.Success = true
	return hop, err
}

func (p *ICMPProber) listenForSpecific4(conn *icmp.PacketConn, neededBody []byte, echoID int, needSeq int, sent []byte) (string, []byte, error) {
	for {
		b := make([]byte, 1500)
		n, peer, err := conn.ReadFrom(b)
		if err != nil {
			if neterr, ok := err.(*net.OpError); ok || neterr.Temporary() {
				return "", []byte{}, neterr
			}
		}
		if n == 0 {
			continue
		}

		x, err := icmp.ParseMessage(protocolICMP, b[:n])
		if err != nil {
			continue
		}

		if x.Type.(ipv4.ICMPType) == ipv4.ICMPTypeTimeExceeded {
			body := x.Body.(*icmp.TimeExceeded).Data
			index := bytes.Index(body, sent[:4])
			if index > 0 {
				x, _ := icmp.ParseMessage(protocolICMP, body[index:])
				switch x.Body.(type) {
				case *icmp.Echo:
					msg := x.Body.(*icmp.Echo)
					if msg.ID == echoID && msg.Seq == needSeq {
						return peer.String(), []byte{}, nil
					}
				default:
					// ignore
				}
			}
		}

		if x.Type.(ipv4.ICMPType) == ipv4.ICMPTypeEchoReply {
			b, _ := x.Body.Marshal(protocolICMP)
			if string(b[4:]) != string(neededBody) || x.Body.(*icmp.Echo).ID != echoID {
				continue
			}

			return peer.String(), b[4:], nil
		}
	}
}

func (p *ICMPProber) listenForSpecific6(conn *icmp.PacketConn, neededBody []byte, echoID int, needSeq int) (string, []byte, error) {
	for {
		b := make([]byte, 1500)
		n, peer, err := conn.ReadFrom(b)
		if err != nil {
			if neterr, ok := err.(*net.OpError); ok {
				return "", []byte{}, neterr
			}
		}
		if n == 0 {
			continue
		}

		x, err := icmp.ParseMessage(protocolIPv6ICMP, b[:n])
		if err != nil {
			continue
		}

		if x.Type.(ipv6.ICMPType) == ipv6.ICMPTypeTimeExceeded {
			body := x.Body.(*icmp.TimeExceeded).Data
			x, _ := icmp.ParseMessage(protocolIPv6ICMP, body[40:])
			switch x.Body.(type) {
			case *icmp.Echo:
				msg := x.Body.(*icmp.Echo)
				if msg.ID == echoID && msg.Seq == needSeq {
					return peer.String(), []byte{}, nil
				}
			default:
				// ignore
			}
		}

		if x.Type.(ipv6.ICMPType) == ipv6.ICMPTypeEchoReply {
			b, _ := x.Body.Marshal(protocolICMP)
			if string(b[4:]) != string(neededBody) || x.Body.(*icmp.Echo).ID != echoID {
				continue
			}

			return peer.String(), b[4:], nil
		}
	}
}
