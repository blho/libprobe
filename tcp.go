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
	// 可以添加 TCP 特定的参数
	Port int
}

type TCPResult struct {
	BaseResult[TCPExtention]
	ConnectTime time.Duration
}

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
