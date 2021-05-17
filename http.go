package libprobe

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptrace"
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
	return "http"
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
	var (
		dnsStartAt          time.Time
		dnsDoneAt           time.Time
		connectStartAt      time.Time
		connectGotAt        time.Time
		connectDoneAt       time.Time
		firstResponseByteAt time.Time
		tlsHandshakeStartAt time.Time
		tlsHandshakeDoneAt  time.Time
		transferDoneAt      time.Time
	)
	clientTrace := &httptrace.ClientTrace{
		DNSStart: func(info httptrace.DNSStartInfo) { dnsStartAt = time.Now() },
		DNSDone: func(info httptrace.DNSDoneInfo) {
			dnsDoneAt = time.Now()
			if info.Err != nil {
				r.Error = info.Err
			}
		},
		ConnectStart: func(_, _ string) {
			connectStartAt = time.Now()
			// Directly connect to IP
			if dnsDoneAt.IsZero() {
				dnsDoneAt = connectStartAt
				dnsStartAt = connectStartAt
			}
		},
		GotConn: func(_ httptrace.GotConnInfo) { connectGotAt = time.Now() },
		ConnectDone: func(net, addr string, err error) {
			connectDoneAt = time.Now()
			if err != nil {
				r.Error = err
			}
		},
		GotFirstResponseByte: func() { firstResponseByteAt = time.Now() },
		TLSHandshakeStart:    func() { tlsHandshakeStartAt = time.Now() },
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			tlsHandshakeDoneAt = time.Now()
			if err != nil {
				r.Error = err
			}
		},
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
	traceRequest := req.WithContext(httptrace.WithClientTrace(context.Background(), clientTrace))
	resp, err := httpClient.Do(traceRequest)
	if err != nil {
		r.Error = err
		return r, nil
	}
	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return r, err
	}
	transferDoneAt = time.Now()
	r.ResponseSize = len(responseBody)
	resp.Body.Close()
	r.ResponseStatusCode = resp.StatusCode

	r.DNSResolveTime = dnsDoneAt.Sub(dnsStartAt)
	r.ConnectTime = connectDoneAt.Sub(connectStartAt)
	r.TLSHandshakeTime = tlsHandshakeDoneAt.Sub(tlsHandshakeStartAt)
	r.TTFB = firstResponseByteAt.Sub(connectGotAt)
	r.TransferTime = transferDoneAt.Sub(firstResponseByteAt)
	r.TotalTime = transferDoneAt.Sub(dnsStartAt)
	return r, nil
}
