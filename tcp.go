package libprobe

import (
	"fmt"
	"net"
	"time"
)

const (
	KindTCP = "TCP"
)

type TCPExtention struct {
	// Port specifies the TCP port to connect to
	Port int
}

type TCPResult struct {
	BaseResult[TCPExtention]
	ConnectTime time.Duration
}

// RTT returns the total round-trip time for TCP connection
func (r TCPResult) RTT() time.Duration {
	return r.Duration
}

func (r TCPResult) String() string {
	if !r.Success {
		return fmt.Sprintf("-> %s error: %s", r.Target.Address, r.Error())
	}
	return fmt.Sprintf("-> %s %s", r.Target.Address, r.RTT())
}

type TCPProber struct{}

func NewTCPProber() *TCPProber {
	return &TCPProber{}
}

func (p *TCPProber) Kind() string {
	return KindTCP
}

func (p *TCPProber) Probe(target Target[TCPExtention]) (Result[TCPExtention], error) {
	r := &TCPResult{
		BaseResult: BaseResult[TCPExtention]{
			Target: target,
		},
	}

	startAt := time.Now()
	conn, err := net.DialTimeout("tcp", target.Address, target.Timeout)
	if err != nil {
		r.Err = err
		return r, nil
	}
	defer conn.Close()

	r.Duration = time.Since(startAt)
	r.Success = true
	return r, nil
}
