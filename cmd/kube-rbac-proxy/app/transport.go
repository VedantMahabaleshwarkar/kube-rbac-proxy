/*
Copyright 2017 Frederic Branczyk All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

var errUpstreamTimeout = errors.New("upstream timeout")

type upstreamTimeoutRoundTripper struct {
	next      http.RoundTripper
	timeout   time.Duration
	now       func() time.Time
	afterFunc func(time.Duration, func()) *time.Timer
}

func withUpstreamTimeout(next http.RoundTripper, timeout time.Duration) http.RoundTripper {
	if timeout <= 0 {
		return next
	}

	return &upstreamTimeoutRoundTripper{
		next:    next,
		timeout: timeout,
	}
}

func (r *upstreamTimeoutRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	now := r.now
	if now == nil {
		now = time.Now
	}
	timeout := r.timeout
	if budget, ok := req.Context().Value(requestTimeoutBudgetContextKey{}).(requestTimeoutBudget); ok && !budget.upstreamDeadline.IsZero() {
		timeout = budget.upstreamDeadline.Sub(now())
	}
	if timeout <= 0 {
		if cause := context.Cause(req.Context()); cause != nil {
			return nil, cause
		}
		return nil, fmt.Errorf("upstream request before response headers: %w", context.DeadlineExceeded)
	}

	ctx, cancel := context.WithCancelCause(req.Context())

	var mu sync.Mutex
	completed := false
	timedOut := false
	var timer *time.Timer
	afterFunc := r.afterFunc
	if afterFunc == nil {
		afterFunc = time.AfterFunc
	}
	timer = afterFunc(timeout, func() {
		mu.Lock()
		if completed {
			mu.Unlock()
			return
		}
		timedOut = true
		cancel(errUpstreamTimeout)
		mu.Unlock()
	})
	resp, err := r.next.RoundTrip(req.WithContext(ctx))

	mu.Lock()
	completed = true
	if timer != nil {
		timer.Stop()
	}
	timeoutWon := timedOut && context.Cause(ctx) == errUpstreamTimeout
	mu.Unlock()

	if timeoutWon {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return nil, fmt.Errorf("upstream request before response headers: %w", context.DeadlineExceeded)
	}

	if err != nil || resp == nil || resp.Body == nil {
		cancel(nil)
		return resp, err
	}

	if readWriteBody, ok := resp.Body.(io.ReadWriteCloser); ok {
		resp.Body = &cancelOnCloseReadWriteCloser{
			ReadWriteCloser: readWriteBody,
			cancel:          cancel,
		}
	} else {
		resp.Body = &cancelOnCloseReadCloser{
			ReadCloser: resp.Body,
			cancel:     cancel,
		}
	}
	return resp, nil
}

type cancelOnCloseReadCloser struct {
	io.ReadCloser
	cancel     context.CancelCauseFunc
	cancelOnce sync.Once
}

func (r *cancelOnCloseReadCloser) Close() error {
	r.cancelOnce.Do(func() {
		r.cancel(nil)
	})
	return r.ReadCloser.Close()
}

type cancelOnCloseReadWriteCloser struct {
	io.ReadWriteCloser
	cancel     context.CancelCauseFunc
	cancelOnce sync.Once
}

func (r *cancelOnCloseReadWriteCloser) Close() error {
	r.cancelOnce.Do(func() {
		r.cancel(nil)
	})
	return r.ReadWriteCloser.Close()
}

func initTransport(upstreamCAPool *x509.CertPool, upstreamClientCertPath, upstreamClientKeyPath string, timeout time.Duration) (http.RoundTripper, error) {
	if upstreamCAPool == nil {
		// Create transport based on DefaultTransport for timeout support
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.ResponseHeaderTimeout = timeout
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{}
		}
		transport.TLSClientConfig.MinVersion = tls.VersionTLS12
		transport.TLSClientConfig.NextProtos = []string{"h2", "http/1.1"}
		return transport, nil
	}

	var certKeyPair tls.Certificate
	if len(upstreamClientCertPath) > 0 {
		var err error
		certKeyPair, err = tls.LoadX509KeyPair(upstreamClientCertPath, upstreamClientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read upstream client cert/key: %w", err)
		}
	}

	// http.Transport sourced from go 1.10.7
	transport := &http.Transport{
		ForceAttemptHTTP2: true,
		Proxy:             http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: timeout,
		TLSClientConfig: &tls.Config{
			RootCAs:    upstreamCAPool,
			MinVersion: tls.VersionTLS12,
		},
	}

	transport.TLSClientConfig.NextProtos = []string{"h2", "http/1.1"}

	if certKeyPair.Certificate != nil {
		transport.TLSClientConfig.Certificates = []tls.Certificate{certKeyPair}
	}

	return transport, nil
}
