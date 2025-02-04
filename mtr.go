/*
Package libprobe implements network probing functionality.

MTR (My TraceRoute) combines the functionality of traceroute and ping.
It works by:
1. Sending ICMP Echo requests with increasing TTL values
2. Collecting ICMP Time Exceeded messages from intermediate routers
3. Recording statistics for each hop including latency, loss rate, and jitter
4. Performing multiple probes to gather accurate statistics

The implementation uses raw sockets to send and receive ICMP packets,
requiring root privileges on most systems.
*/
package libprobe

import (
	"fmt"
	"math"
	"net"
	"sort"
	"time"
)

// MTRHop represents a single hop in the route
type MTRHop struct {
	TTL       int           // Time To Live value
	Address   string        // IP address of the hop
	Hostname  string        // DNS name (if resolvable)
	Loss      float64       // Packet loss percentage
	LastRTT   time.Duration // Last Round Trip Time
	AvgRTT    time.Duration // Average Round Trip Time
	BestRTT   time.Duration // Best Round Trip Time
	WorstRTT  time.Duration // Worst Round Trip Time
	StdDevRTT time.Duration // Standard deviation of RTT
	Sent      int           // Number of packets sent
	Received  int           // Number of packets received
}

// MTRResult contains the complete MTR probe results
type MTRResult struct {
	BaseResult[MTRExtention]
	Hops []MTRHop // All hops in the route
}

// MTRExtention contains MTR-specific parameters
type MTRExtention struct {
	ICMPExtention
	MaxHops    int  // Maximum number of hops to probe
	ResolvePtr bool // Whether to resolve PTR records
}

func (r MTRResult) String() string {
	if !r.Success {
		return "MTR probe failed"
	}

	result := fmt.Sprintf("MTR to %s\n", r.Target.Address)
	result += "HOP  ADDRESS                  LOSS%  SENT  RECV  LAST   AVG    BEST   WORST  STDEV\n"

	for _, hop := range r.Hops {
		hostname := hop.Address
		if hop.Hostname != "" {
			hostname = fmt.Sprintf("%s (%s)", hop.Hostname, hop.Address)
		}

		result += fmt.Sprintf("%-4d %-24s %5.1f%% %4d  %4d  %6s %6s %6s %6s %6s\n",
			hop.TTL,
			hostname,
			hop.Loss,
			hop.Sent,
			hop.Received,
			hop.LastRTT.Round(time.Millisecond),
			hop.AvgRTT.Round(time.Millisecond),
			hop.BestRTT.Round(time.Millisecond),
			hop.WorstRTT.Round(time.Millisecond),
			hop.StdDevRTT.Round(time.Millisecond),
		)
	}
	return result
}

// MTRProber MTR 探测器
// MTRProber implements the MTR (My TraceRoute) probe functionality
type MTRProber struct {
	icmpID *IcmpID
}

// NewMTRProber creates a new MTR prober instance
func NewMTRProber() *MTRProber {
	return &MTRProber{
		icmpID: &IcmpID{},
	}
}

// Kind returns the probe type identifier
func (p *MTRProber) Kind() string {
	return "MTR"
}

// Probe performs the MTR probe operation
func (p *MTRProber) Probe(target Target[MTRExtention]) (Result[MTRExtention], error) {
	r := &MTRResult{
		BaseResult: BaseResult[MTRExtention]{
			Target: target,
		},
		Hops: make([]MTRHop, 0),
	}

	maxHops := 30 // default maximum number of hops
	if target.Extention.MaxHops > 0 {
		maxHops = target.Extention.MaxHops
	}

	// Create statistics map for each hop
	hopStats := make(map[string]*hopStat)

	// Send probes with increasing TTL values
	for ttl := 1; ttl <= maxHops; ttl++ {
		hop, err := p.probeHop(target, ttl)
		if err != nil {
			continue
		}

		// Update statistics for this hop
		stat := getOrCreateHopStat(hopStats, hop.Address)
		stat.update(hop.LastRTT)

		// Check if we've reached the target
		if hop.Address == target.Address {
			// Send additional probes to gather more accurate statistics
			for i := 0; i < target.GetCount()-1; i++ {
				if hop, err := p.probeHop(target, ttl); err == nil {
					stat.update(hop.LastRTT)
				}
			}
			break
		}
	}

	// Compile results
	hops := make([]MTRHop, 0, len(hopStats))
	for _, stat := range hopStats {
		mtrHop := MTRHop{
			TTL:      stat.ttl,
			Address:  stat.address,
			LastRTT:  stat.lastRTT,
			AvgRTT:   stat.avgRTT(),
			BestRTT:  stat.bestRTT,
			WorstRTT: stat.worstRTT,
			Sent:     stat.sent,
			Received: stat.received,
			Loss:     stat.lossRate() * 100,
		}

		// Resolve hostname if requested
		if target.Extention.ResolvePtr {
			names, err := net.LookupAddr(stat.address)
			if err == nil && len(names) > 0 {
				mtrHop.Hostname = names[0]
			}
		}

		hops = append(hops, mtrHop)
	}

	// Sort hops by TTL
	sort.Sort(hopsByTTL(hops))
	r.Hops = hops

	r.Success = true
	return r, nil
}

// probeHop sends a probe with specified TTL and returns hop information
func (p *MTRProber) probeHop(target Target[MTRExtention], ttl int) (*MTRHop, error) {
	// Create ICMP probe request
	icmpTarget := Target[ICMPExtention]{
		Address: target.Address,
		Timeout: target.Timeout,
		Count:   1,
		Extention: ICMPExtention{
			TTL:      ttl,
			Size:     target.Extention.ICMPExtention.Size,
			SourceIP: target.Extention.ICMPExtention.SourceIP,
			EnableV6: target.Extention.ICMPExtention.EnableV6,
			Sequence: target.Extention.ICMPExtention.Sequence,
		},
	}

	// Perform ICMP probe
	result, err := NewICMPProber().Probe(icmpTarget)
	if err != nil {
		return nil, err
	}

	icmpResult := result.(*ICMPResult)
	return &MTRHop{
		TTL:     ttl,
		Address: icmpResult.Address,
		LastRTT: icmpResult.Duration,
	}, nil
}

// Internal helper types and methods
type hopStat struct {
	ttl      int
	address  string
	lastRTT  time.Duration
	bestRTT  time.Duration
	worstRTT time.Duration
	sumRTT   time.Duration
	sent     int
	received int
	rtts     []time.Duration
}

func (h *hopStat) update(rtt time.Duration) {
	h.sent++
	if rtt > 0 {
		h.received++
		h.lastRTT = rtt
		h.sumRTT += rtt
		h.rtts = append(h.rtts, rtt)

		if h.bestRTT == 0 || rtt < h.bestRTT {
			h.bestRTT = rtt
		}
		if rtt > h.worstRTT {
			h.worstRTT = rtt
		}
	}
}

func (h *hopStat) avgRTT() time.Duration {
	if h.received == 0 {
		return 0
	}
	return h.sumRTT / time.Duration(h.received)
}

func (h *hopStat) lossRate() float64 {
	if h.sent == 0 {
		return 0
	}
	return float64(h.sent-h.received) / float64(h.sent)
}

func (h *hopStat) stdDevRTT() time.Duration {
	if h.received < 2 {
		return 0
	}

	avg := h.avgRTT()
	var sum float64
	for _, rtt := range h.rtts {
		diff := float64(rtt - avg)
		sum += diff * diff
	}

	variance := sum / float64(len(h.rtts)-1)
	return time.Duration(math.Sqrt(variance))
}

func getOrCreateHopStat(stats map[string]*hopStat, addr string) *hopStat {
	if stat, exists := stats[addr]; exists {
		return stat
	}
	stats[addr] = &hopStat{
		address: addr,
		ttl:     len(stats) + 1, // 设置正确的 TTL
	}
	return stats[addr]
}

// 按 TTL 排序的 hop 列表
type hopsByTTL []MTRHop

func (h hopsByTTL) Len() int           { return len(h) }
func (h hopsByTTL) Less(i, j int) bool { return h[i].TTL < h[j].TTL }
func (h hopsByTTL) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
