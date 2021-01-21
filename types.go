package libprobe

import (
	"net/http"
	"time"
)

type Target struct {
	// Can be a IP, IP:Port or URL
	Address string
	Timeout time.Duration
	Count   int

	// HTTP Probe only
	Headers http.Header
}

func (t Target) GetCount() int {
	if t.Count == 0 {
		return 1
	}
	return t.Count
}

type Result interface {
	RTT() time.Duration
	String() string
}

type Prober interface {
	Kind() string
	Probe(target Target) (Result, error)
}
