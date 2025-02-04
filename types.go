package libprobe

import (
	"io"
	"net/http"
	"time"
)

// Target defines a probe target with generic extension parameters
type Target[T any] struct {
	// Address can be an IP, IP:Port or URL
	Address string
	// Timeout for the entire probe operation
	Timeout time.Duration
	// Interval between multiple probes
	Interval time.Duration
	// Number of probes to send
	Count int

	// Extension parameters specific to each probe type
	Extention T

	// DEPRECATED: These fields will be moved to respective Extensions
	RequestMethod string
	Headers       http.Header
	Body          io.Reader
}

func (t Target[T]) GetCount() int {
	if t.Count == 0 {
		return 1
	}
	return t.Count
}

// Result defines the interface for probe results
type Result[T any] interface {
	// RTT returns the round-trip time of the probe
	RTT() time.Duration
	// String returns a human-readable representation of the result
	String() string
	// GetTarget returns the original probe target
	GetTarget() Target[T]
	// IsSuccess returns whether the probe was successful
	IsSuccess() bool
	// Error returns any error that occurred during probing
	Error() error
}

// BaseResult 提供基础结果实现
type BaseResult[T any] struct {
	Target    Target[T]
	Success   bool
	Err       error
	Duration  time.Duration
	StartTime time.Time
	EndTime   time.Time
}

func (r BaseResult[T]) RTT() time.Duration {
	return r.Duration
}

func (r BaseResult[T]) GetTarget() Target[T] {
	return r.Target
}

func (r BaseResult[T]) IsSuccess() bool {
	return r.Success
}

func (r BaseResult[T]) Error() error {
	return r.Err
}

func (r *BaseResult[T]) start() {
	r.StartTime = time.Now()
}

func (r *BaseResult[T]) end() {
	r.EndTime = time.Now()
	r.Duration = r.EndTime.Sub(r.StartTime)
}

// Prober 定义探测器接口
type Prober[T any] interface {
	Kind() string
	Probe(target Target[T]) (Result[T], error)
}
