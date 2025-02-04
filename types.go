package libprobe

import (
	"io"
	"net/http"
	"time"
)

// Target 定义探测目标
type Target[T any] struct {
	// Can be a IP, IP:Port or URL
	Address  string
	Timeout  time.Duration
	Interval time.Duration
	Count    int

	Extention T

	// DEPRECATED: move to Extention
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

// Result 定义探测结果接口
type Result[T any] interface {
	// 基础结果接口
	RTT() time.Duration
	String() string
	// 获取原始目标
	GetTarget() Target[T]
	// 是否成功
	IsSuccess() bool
	// 获取错误信息
	Error() error
}

// BaseResult 提供基础结果实现
type BaseResult[T any] struct {
	Target   Target[T]
	Success  bool
	Err      error
	Duration time.Duration
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

// Prober 定义探测器接口
type Prober[T any] interface {
	Kind() string
	Probe(target Target[T]) (Result[T], error)
}
