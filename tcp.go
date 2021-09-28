package libprobe

import (
	"fmt"
	"net"
	"time"
)

type TCPProber struct {
}

func NewTCPProber() *TCPProber {
	return &TCPProber{}
}

func (p *TCPProber) Kind() string {
	return KindTCP
}

type TCPResult struct {
	Target
	Error       error
	ConnectTime time.Duration
}

func (r TCPResult) RTT() time.Duration {
	return r.ConnectTime
}

func (r TCPResult) String() string {
	return fmt.Sprintf("-> %s %s", r.Target.Address, r.RTT())
}

func (p *TCPProber) Probe(target Target) (Result, error) {
	r := &TCPResult{
		Target: target,
	}
	// TODO: Add resolve
	startAt := time.Now()
	conn, err := net.DialTimeout("tcp", r.Address, r.Timeout)
	if err != nil {
		r.Error = err
		return r, nil
	}
	_ = conn.Close()
	r.ConnectTime = time.Since(startAt)
	return r, nil
}
