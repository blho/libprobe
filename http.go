package libprobe

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

const (
	KindHTTP = "HTTP"
)

type HTTPExtention struct {
	// HTTP 特定的参数
	Method  string
	Headers http.Header
	Body    []byte
}

type HTTPResult struct {
	BaseResult[HTTPExtention]
	DNSResolveTime   time.Duration
	ConnectTime      time.Duration
	TLSHandshakeTime time.Duration
	TTFB             time.Duration
	TransferTime     time.Duration
	StatusCode       int
	ResponseSize     int
	ResponseBody     []byte
}

func (r HTTPResult) RTT() time.Duration {
	return r.Duration
}

const (
	httpsTemplate = `` +
		`  DNS Lookup   TCP Connection   TLS Handshake   Server Processing   Content Transfer` + "\n" +
		`[%s  |     %s  |    %s  |        %s  |       %s  ]` + "\n" +
		"Total: %s\n"
	httpTemplate = `` +
		`   DNS Lookup   TCP Connection   Server Processing   Content Transfer` + "\n" +
		`[ %s  |     %s  |        %s  |       %s  ]` + "\n" +
		"Total: %s\n"
)

func (r HTTPResult) String() string {
	if err := r.Error(); err != nil {
		return fmt.Sprintf("Error: %s", err)
	}
	if strings.HasPrefix(r.Target.Address, "http://") {
		return fmt.Sprintf(httpTemplate, r.DNSResolveTime, r.ConnectTime, r.TTFB, r.TransferTime, r.Duration)
	} else if strings.HasPrefix(r.Target.Address, "https://") {
		return fmt.Sprintf(httpsTemplate, r.DNSResolveTime, r.ConnectTime, r.TLSHandshakeTime, r.TTFB, r.TransferTime, r.Duration)
	}

	return fmt.Sprintf("Error: %s; "+
		"DNS Resolve: %s, Connect: %s, TLS Handshake: %s, TTFB: %s, Transfer: %s. Total: %s",
		r.Error(),
		r.DNSResolveTime, r.ConnectTime, r.TLSHandshakeTime, r.TTFB, r.TransferTime, r.Duration)
}

type HTTPProber struct{}

func NewHTTPProber() *HTTPProber {
	return &HTTPProber{}
}

func (p *HTTPProber) Kind() string {
	return KindHTTP
}

func (p *HTTPProber) Probe(target Target[HTTPExtention]) (Result[HTTPExtention], error) {
	r := &HTTPResult{
		BaseResult: BaseResult[HTTPExtention]{
			Target: target,
		},
	}

	method := target.Extention.Method
	if method == "" {
		method = "GET"
	}

	req, err := http.NewRequest(method, target.Address, nil)
	if err != nil {
		r.Err = err
		return r, nil
	}

	if target.Extention.Headers != nil {
		req.Header = target.Extention.Headers
	}

	httpClient := &http.Client{
		Timeout:   target.Timeout,
		Transport: &http.Transport{},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	trace := &HTTPClientTrace{}
	traceRequest := req.WithContext(trace.CreateContext(context.Background()))

	resp, err := httpClient.Do(traceRequest)
	if err != nil {
		r.Err = err
		return r, nil
	}
	defer resp.Body.Close()

	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return r, err
	}

	transferDoneAt := time.Now()
	r.ResponseSize = len(responseBody)
	r.StatusCode = resp.StatusCode

	traceInfo := trace.TraceInfo()
	r.DNSResolveTime = traceInfo.DNSLookup
	r.ConnectTime = traceInfo.ConnTime
	r.TLSHandshakeTime = traceInfo.TLSHandshake
	r.TTFB = traceInfo.TTFB
	r.TransferTime = transferDoneAt.Sub(traceInfo.FirstResponseByteAt)
	r.Duration = transferDoneAt.Sub(traceInfo.RequestStartAt)

	return r, nil
}
