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

var errResponseHeaderTimeout = errors.New("response header timeout")

type responseHeaderTimeoutRoundTripper struct {
	next      http.RoundTripper
	timeout   time.Duration
	afterFunc func(time.Duration, func()) *time.Timer
}

func withResponseHeaderTimeout(next http.RoundTripper, timeout time.Duration) http.RoundTripper {
	if timeout <= 0 {
		return next
	}

	return &responseHeaderTimeoutRoundTripper{
		next:    next,
		timeout: timeout,
	}
}

func (r *responseHeaderTimeoutRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithCancelCause(req.Context())

	var mu sync.Mutex
	completed := false
	timedOut := false
	afterFunc := r.afterFunc
	if afterFunc == nil {
		afterFunc = time.AfterFunc
	}
	timer := afterFunc(r.timeout, func() {
		mu.Lock()
		defer mu.Unlock()
		if completed {
			return
		}

		timedOut = true
		cancel(errResponseHeaderTimeout)
	})
	resp, err := r.next.RoundTrip(req.WithContext(ctx))

	mu.Lock()
	if !timedOut {
		completed = true
		timer.Stop()
	}
	timeoutWon := timedOut && context.Cause(ctx) == errResponseHeaderTimeout
	mu.Unlock()

	if timeoutWon {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return nil, fmt.Errorf("upstream response headers: %w", context.DeadlineExceeded)
	}

	if err != nil || resp == nil || resp.Body == nil {
		cancel(nil)
		return resp, err
	}

	resp.Body = &cancelOnCloseReadCloser{
		ReadCloser: resp.Body,
		cancel:     cancel,
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
