package libprobe

import (
	"fmt"
	"time"

	"github.com/go-ping/ping"
)

type ICMPResult struct {
	Target

	Stats *ping.Statistics
}

const (
	icmpTemplate = `%d packets transmitted, %d packets received, %v%% packet loss
round-trip min/avg/max/stddev = %v/%v/%v/%v`
)

func (r ICMPResult) RTT() time.Duration {
	return r.Stats.AvgRtt
}

func (r ICMPResult) String() string {
	if r.Stats == nil {
		return "ICMP probe no result"
	}
	return fmt.Sprintf(icmpTemplate, r.Stats.PacketsSent, r.Stats.PacketsRecv, r.Stats.PacketLoss,
		r.Stats.MinRtt, r.Stats.AvgRtt, r.Stats.MaxRtt, r.Stats.StdDevRtt)
}

type ICMPProber struct {
	privileged bool
}

func NewICMPProber(privileged bool) *ICMPProber {
	return &ICMPProber{
		privileged: privileged,
	}
}

func (p *ICMPProber) Kind() string {
	return "ICMP"
}

func (p *ICMPProber) Probe(target Target) (Result, error) {
	r := &ICMPResult{
		Target: target,
	}
	pinger, err := ping.NewPinger(target.Address)
	if err != nil {
		return nil, err
	}
	pinger.SetPrivileged(p.privileged)
	pinger.Count = target.GetCount()
	if target.Timeout.Seconds() > 0 {
		pinger.Timeout = target.Timeout
	}
	if target.Interval.Seconds() > 0 {
		pinger.Interval = target.Interval
	}
	err = pinger.Run()
	if err != nil {
		return nil, err
	}
	r.Stats = pinger.Statistics()
	return r, nil
}
