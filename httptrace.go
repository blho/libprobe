package libprobe

import (
	"context"
	"crypto/tls"
	"net"
	"net/http/httptrace"
	"time"
)

type HTTPClientTrace struct {
	failedOn             string
	getConn              time.Time
	dnsStart             time.Time
	dnsDone              time.Time
	connectDone          time.Time
	tlsHandshakeStart    time.Time
	tlsHandshakeDone     time.Time
	gotConn              time.Time
	gotFirstResponseByte time.Time
	endTime              time.Time
	gotConnInfo          httptrace.GotConnInfo
}

const (
	HTTPStepDNSLookup    = "DNS_LOOKUP"
	HTTPStepConnect      = "CONNECT"
	HTTPStepTLSHandshake = "TLS_HANDSHAKE"
)

func (t *HTTPClientTrace) CreateContext(ctx context.Context) context.Context {
	return httptrace.WithClientTrace(
		ctx,
		&httptrace.ClientTrace{
			DNSStart: func(_ httptrace.DNSStartInfo) {
				t.dnsStart = time.Now()
			},
			DNSDone: func(info httptrace.DNSDoneInfo) {
				t.dnsDone = time.Now()
				if info.Err != nil {
					t.failedOn = HTTPStepDNSLookup
				}
			},
			ConnectStart: func(_, _ string) {
				if t.dnsDone.IsZero() {
					t.dnsDone = time.Now()
				}
				if t.dnsStart.IsZero() {
					t.dnsStart = t.dnsDone
				}
			},
			GetConn: func(_ string) {
				t.getConn = time.Now()
			},
			GotConn: func(ci httptrace.GotConnInfo) {
				t.gotConn = time.Now()
				t.gotConnInfo = ci
			},
			ConnectDone: func(net, addr string, err error) {
				t.connectDone = time.Now()
				if err != nil {
					t.failedOn = HTTPStepConnect
				}
			},
			GotFirstResponseByte: func() {
				t.gotFirstResponseByte = time.Now()
			},
			TLSHandshakeStart: func() {
				t.tlsHandshakeStart = time.Now()
			},
			TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
				t.tlsHandshakeDone = time.Now()
				if err != nil {
					t.failedOn = HTTPStepTLSHandshake
				}
			},
		},
	)
}

type HTTPTraceInfo struct {
	// FailedStep is the step name that failed while requesting.
	FailedStep string

	// DNSLookup is a duration that transport took to perform
	// DNS lookup.
	DNSLookup time.Duration

	// ConnTime is a duration that took to obtain a successful connection.
	ConnTime time.Duration

	// TCPConnTime is a duration that took to obtain the TCP connection.
	TCPConnTime time.Duration

	// TLSHandshake is a duration that TLS handshake took place.
	TLSHandshake time.Duration

	// TTFB(TimeToFirstByte) is a duration that server took to respond first byte.
	TTFB time.Duration

	// ResponseTime is a duration since first response byte from server to
	// request completion.
	ResponseTime time.Duration

	// TotalTime is a duration that total request took end-to-end.
	TotalTime time.Duration

	// IsConnReused is whether this connection has been previously
	// used for another HTTP request.
	IsConnReused bool

	// IsConnWasIdle is whether this connection was obtained from an
	// idle pool.
	IsConnWasIdle bool

	// ConnIdleTime is a duration how long the connection was previously
	// idle, if IsConnWasIdle is true.
	ConnIdleTime time.Duration

	// RemoteAddr returns the remote network address.
	RemoteAddr net.Addr

	// Timestamps
	RequestStartAt      time.Time
	FirstResponseByteAt time.Time
}

func (t HTTPClientTrace) TraceInfo() HTTPTraceInfo {
	ti := HTTPTraceInfo{
		FailedStep:          t.failedOn,
		DNSLookup:           t.dnsDone.Sub(t.dnsStart),
		TLSHandshake:        t.tlsHandshakeDone.Sub(t.tlsHandshakeStart),
		TTFB:                t.gotFirstResponseByte.Sub(t.gotConn),
		IsConnReused:        t.gotConnInfo.Reused,
		IsConnWasIdle:       t.gotConnInfo.WasIdle,
		ConnIdleTime:        t.gotConnInfo.IdleTime,
		RequestStartAt:      t.dnsStart,
		FirstResponseByteAt: t.gotFirstResponseByte,
	}

	// Calculate the total time accordingly,
	// when connection is reused
	if t.gotConnInfo.Reused {
		ti.TotalTime = t.endTime.Sub(t.getConn)
	} else {
		ti.TotalTime = t.endTime.Sub(t.dnsStart)
	}

	// Only calculate on successful connections
	if !t.connectDone.IsZero() {
		ti.TCPConnTime = t.connectDone.Sub(t.dnsDone)
	}

	// Only calculate on successful connections
	if !t.gotConn.IsZero() {
		ti.ConnTime = t.gotConn.Sub(t.getConn)
	}

	// Only calculate on successful connections
	if !t.gotFirstResponseByte.IsZero() {
		ti.ResponseTime = t.endTime.Sub(t.gotFirstResponseByte)
	}

	// Capture remote address info when connection is non-nil
	if t.gotConnInfo.Conn != nil {
		ti.RemoteAddr = t.gotConnInfo.Conn.RemoteAddr()
	}
	return ti
}
