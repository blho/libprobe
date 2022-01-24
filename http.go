package libprobe

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

type HTTPResult struct {
	Target
	Error              error
	DNSResolveTime     time.Duration
	ConnectTime        time.Duration
	TLSHandshakeTime   time.Duration
	TTFB               time.Duration
	TransferTime       time.Duration
	TotalTime          time.Duration
	ResponseStatusCode int
	ResponseSize       int
	ResponseBody       []byte
}

func (r HTTPResult) RTT() time.Duration {
	return r.TotalTime
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
	if r.Error != nil {
		return fmt.Sprintf("Error: %s", r.Error)
	}
	if strings.HasPrefix(r.Address, "http://") {
		return fmt.Sprintf(httpTemplate, r.DNSResolveTime, r.ConnectTime, r.TTFB, r.TransferTime, r.TotalTime)
	} else if strings.HasPrefix(r.Address, "https://") {
		return fmt.Sprintf(httpsTemplate, r.DNSResolveTime, r.ConnectTime, r.TLSHandshakeTime, r.TTFB, r.TransferTime, r.TotalTime)
	}

	return fmt.Sprintf("Error: %s; "+
		"DNS Resolve: %s, Connect: %s, TLS Handshake: %s, TTFB: %s, Transfer: %s. Total: %s",
		r.Error,
		r.DNSResolveTime, r.ConnectTime, r.TLSHandshakeTime, r.TTFB, r.TransferTime, r.TotalTime)
}

type HTTPProber struct {
}

func NewHTTPProber() *HTTPProber {
	return &HTTPProber{}
}

func (p *HTTPProber) Kind() string {
	return KindHTTP
}

func (p *HTTPProber) Probe(target Target) (Result, error) {
	r := &HTTPResult{
		Target: target,
	}
	req, err := http.NewRequest(target.RequestMethod, target.Address, target.Body)
	if err != nil {
		return r, err
	}
	if target.Headers != nil {
		req.Header = target.Headers
	}

	httpClient := &http.Client{
		Timeout:   target.Timeout,
		Transport: &http.Transport{},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// always refuse to follow redirects, visit does that
			// manually if required.
			return http.ErrUseLastResponse
		},
	}
	trace := &HTTPClientTrace{}
	traceRequest := req.WithContext(trace.CreateContext(context.Background()))
	resp, err := httpClient.Do(traceRequest)
	if err != nil {
		r.Error = err
		return r, nil
	}
	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return r, err
	}
	transferDoneAt := time.Now()
	r.ResponseSize = len(responseBody)
	resp.Body.Close()
	r.ResponseStatusCode = resp.StatusCode
	traceInfo := trace.TraceInfo()
	r.DNSResolveTime = traceInfo.DNSLookup
	r.ConnectTime = traceInfo.ConnTime
	r.TLSHandshakeTime = traceInfo.TLSHandshake
	r.TTFB = traceInfo.TTFB
	r.TransferTime = transferDoneAt.Sub(traceInfo.FirstResponseByteAt)
	r.TotalTime = transferDoneAt.Sub(traceInfo.RequestStartAt)
	return r, nil
}
