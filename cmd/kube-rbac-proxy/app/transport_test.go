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
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	certutil "k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"
)

type stubRoundTripper struct {
	roundTrip func(*http.Request) (*http.Response, error)
}

func (s *stubRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return s.roundTrip(req)
}

type contextAwareBody struct {
	ctx     context.Context
	payload string
	delay   time.Duration
	read    bool
}

func (b *contextAwareBody) Read(p []byte) (int, error) {
	if b.read {
		return 0, io.EOF
	}

	timer := time.NewTimer(b.delay)
	defer timer.Stop()
	select {
	case <-b.ctx.Done():
		return 0, context.Cause(b.ctx)
	case <-timer.C:
	}

	b.read = true
	return copy(p, b.payload), nil
}

func (*contextAwareBody) Close() error {
	return nil
}

type notifyingBody struct {
	io.Reader
	closed chan struct{}
}

func (b *notifyingBody) Close() error {
	close(b.closed)
	return nil
}

func TestWithResponseHeaderTimeoutDisabledReturnsUnderlyingTransport(t *testing.T) {
	next := &stubRoundTripper{roundTrip: func(*http.Request) (*http.Response, error) {
		return nil, nil
	}}

	for _, timeout := range []time.Duration{0, -time.Second} {
		if got := withResponseHeaderTimeout(next, timeout); got != next {
			t.Errorf("withResponseHeaderTimeout(%v) returned %T, want underlying transport", timeout, got)
		}
	}
}

func TestResponseHeaderTimeoutReturnsDeadlineExceeded(t *testing.T) {
	closed := make(chan struct{})
	next := &stubRoundTripper{roundTrip: func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return &http.Response{
			StatusCode: http.StatusOK,
			Body: &notifyingBody{
				Reader: strings.NewReader("late response"),
				closed: closed,
			},
		}, context.Cause(req.Context())
	}}

	req, err := http.NewRequest(http.MethodGet, "http://upstream.example", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := withResponseHeaderTimeout(next, 10*time.Millisecond).RoundTrip(req)
	if resp != nil {
		t.Fatalf("response = %#v, want nil", resp)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context.DeadlineExceeded", err)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("response body was not closed when the timeout won")
	}
}

func TestResponseHeaderTimeoutPreservesStreamingBody(t *testing.T) {
	const payload = "streamed after headers"
	timeout := 10 * time.Millisecond
	next := &stubRoundTripper{roundTrip: func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body: &contextAwareBody{
				ctx:     req.Context(),
				payload: payload,
				delay:   3 * timeout,
			},
		}, nil
	}}

	req, err := http.NewRequest(http.MethodGet, "http://upstream.example", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := withResponseHeaderTimeout(next, timeout).RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer resp.Body.Close()

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body after response header timeout elapsed: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("body = %q, want %q", got, payload)
	}
}

func TestResponseHeaderTimeoutBodyCloseCancelsChildContext(t *testing.T) {
	requestContext := make(chan context.Context, 1)
	next := &stubRoundTripper{roundTrip: func(req *http.Request) (*http.Response, error) {
		requestContext <- req.Context()
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("response")),
		}, nil
	}}

	req, err := http.NewRequest(http.MethodGet, "http://upstream.example", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := withResponseHeaderTimeout(next, time.Second).RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	ctx := <-requestContext
	select {
	case <-ctx.Done():
		t.Fatal("child context canceled before response body close")
	default:
	}

	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close body: %v", err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("child context was not canceled by response body close")
	}
}

func TestResponseHeaderTimeoutBodyCloseCancelsExactlyOnce(t *testing.T) {
	var cancelCalls atomic.Int32
	body := &cancelOnCloseReadCloser{
		ReadCloser: io.NopCloser(strings.NewReader("response")),
		cancel: func(error) {
			cancelCalls.Add(1)
		},
	}

	for i := 0; i < 2; i++ {
		if err := body.Close(); err != nil {
			t.Fatalf("close body %d: %v", i+1, err)
		}
	}
	if got := cancelCalls.Load(); got != 1 {
		t.Fatalf("cancel calls = %d, want 1 after repeated response body close", got)
	}
}

func TestResponseHeaderTimeoutNilBodyCancelsChildContext(t *testing.T) {
	requestContext := make(chan context.Context, 1)
	next := &stubRoundTripper{roundTrip: func(req *http.Request) (*http.Response, error) {
		requestContext <- req.Context()
		return &http.Response{StatusCode: http.StatusNoContent}, nil
	}}

	req, err := http.NewRequest(http.MethodGet, "http://upstream.example", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if _, err := withResponseHeaderTimeout(next, time.Second).RoundTrip(req); err != nil {
		t.Fatalf("round trip: %v", err)
	}
	ctx := <-requestContext
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("child context was not canceled for a nil response body")
	}
}

func TestResponseHeaderTimeoutRoundTripErrorCancelsChildContext(t *testing.T) {
	requestContext := make(chan context.Context, 1)
	wantErr := errors.New("upstream round trip failed")
	next := &stubRoundTripper{roundTrip: func(req *http.Request) (*http.Response, error) {
		requestContext <- req.Context()
		return nil, wantErr
	}}

	req, err := http.NewRequest(http.MethodGet, "http://upstream.example", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := withResponseHeaderTimeout(next, time.Second).RoundTrip(req)
	if resp != nil {
		t.Fatalf("response = %#v, want nil", resp)
	}
	if err != wantErr {
		t.Fatalf("error = %v, want unchanged RoundTrip error %v", err, wantErr)
	}
	ctx := <-requestContext
	select {
	case <-ctx.Done():
		if cause := context.Cause(ctx); cause != context.Canceled {
			t.Fatalf("child context cause = %v, want context.Canceled", cause)
		}
	default:
		t.Fatal("child context was not canceled before RoundTrip returned its error")
	}
}

func TestResponseHeaderTimeoutPreservesParentCancellation(t *testing.T) {
	timeout := 100 * time.Millisecond
	parentErr := errors.New("parent request canceled")
	started := make(chan struct{})
	observedParentCancellation := make(chan error, 1)
	next := &stubRoundTripper{roundTrip: func(req *http.Request) (*http.Response, error) {
		close(started)
		<-req.Context().Done()
		cause := context.Cause(req.Context())
		observedParentCancellation <- cause
		time.Sleep(2 * timeout)
		return nil, cause
	}}

	ctx, cancel := context.WithCancelCause(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://upstream.example", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := withResponseHeaderTimeout(next, timeout).RoundTrip(req)
		result <- err
	}()

	<-started
	cancel(parentErr)
	select {
	case cause := <-observedParentCancellation:
		if cause != parentErr {
			t.Fatalf("transport observed cancellation cause %v, want %v", cause, parentErr)
		}
	case <-time.After(time.Second):
		t.Fatal("transport did not observe parent cancellation")
	}
	select {
	case err := <-result:
		if err != parentErr {
			t.Fatalf("error = %v, want unchanged parent cancellation %v", err, parentErr)
		}
		if errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("error = %v, must remain distinguishable from response header timeout", err)
		}
	case <-time.After(time.Second):
		t.Fatal("round trip did not return after parent cancellation")
	}
}

func TestInitTransportWithDefault(t *testing.T) {
	roundTripper, err := initTransport(nil, "", "", 0)
	if err != nil {
		t.Errorf("want err to be nil, but got %v", err)
		return
	}
	if roundTripper == nil {
		t.Error("expected roundtripper, got nil")
	}
}

func TestInitTransportTimeoutVariations(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
	}{
		{name: "zero leaves response header timeout unset", timeout: 0},
		{name: "five second response header timeout", timeout: 5 * time.Second},
		{name: "custom short timeout", timeout: 100 * time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			roundTripper, err := initTransport(nil, "", "", tt.timeout)
			if err != nil {
				t.Fatalf("initTransport: %v", err)
			}
			transport := roundTripper.(*http.Transport)
			if transport.ResponseHeaderTimeout != tt.timeout {
				t.Fatalf("ResponseHeaderTimeout = %v, want %v", transport.ResponseHeaderTimeout, tt.timeout)
			}
		})
	}
}

func TestInitTransportTimeoutWithCA(t *testing.T) {
	want := 10 * time.Second
	upstreamCAPEM, err := os.ReadFile("../../../test/ca.pem")
	if err != nil {
		t.Fatalf("failed to read '../../../test/ca.pem': %v", err)
	}

	upstreamCAPool := x509.NewCertPool()
	upstreamCAPool.AppendCertsFromPEM(upstreamCAPEM)

	roundTripper, err := initTransport(upstreamCAPool, "", "", want)
	if err != nil {
		t.Fatalf("want err to be nil, but got %v", err)
	}
	transport := roundTripper.(*http.Transport)
	if transport.ResponseHeaderTimeout != want {
		t.Fatalf("ResponseHeaderTimeout = %v, want %v", transport.ResponseHeaderTimeout, want)
	}
	if transport.TLSClientConfig.RootCAs == nil {
		t.Fatal("expected root CA to be set, got nil")
	}
}

func TestInitTransportWithCustomCA(t *testing.T) {
	upstreamCAPEM, err := os.ReadFile("../../../test/ca.pem")
	if err != nil {
		t.Fatalf("failed to read '../../../test/ca.pem': %v", err)
	}

	upstreamCAPool := x509.NewCertPool()
	upstreamCAPool.AppendCertsFromPEM(upstreamCAPEM)

	roundTripper, err := initTransport(upstreamCAPool, "", "", 0)
	if err != nil {
		t.Fatalf("want err to be nil, but got %v", err)
	}
	transport := roundTripper.(*http.Transport)
	if transport.TLSClientConfig.RootCAs == nil {
		t.Error("expected root CA to be set, got nil")
	}
}

func testHTTPHandler(w http.ResponseWriter, req *http.Request) {
	if len(req.TLS.PeerCertificates) > 0 {
		_, _ = w.Write([]byte("ok"))
		return
	} else {
		reqDump, _ := httputil.DumpRequest(req, false)
		resp := fmt.Sprintf("got request without client certificates:\n%s\n", reqDump)
		resp += fmt.Sprintf("TLS config: %#v\n", req.TLS)
		http.Error(w, resp, http.StatusBadRequest)
	}
}

func TestInitTransportWithClientCertAuth(t *testing.T) {
	tlsServer := http.Server{
		Handler: http.HandlerFunc(testHTTPHandler),
	}

	cert, key, err := certutil.GenerateSelfSignedCertKey("127.0.0.1", nil, nil)
	if err != nil {
		t.Fatalf("failed to create a new serving cert: %v", err)
	}

	tlsCert, err := tls.X509KeyPair(cert, key)
	if err != nil {
		t.Fatalf("failed to load a new serving cert: %v", err)
	}

	clientCert, clientKey, clientCA, err := generateClientCert(t)
	if err != nil {
		t.Fatalf("failed to generate client cert: %v", err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on secure address: %v", err)
	}
	defer l.Close()
	tlsListener := tls.NewListener(l, &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		ClientCAs:    clientCA,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	})
	defer tlsListener.Close()

	go func() {
		if err := tlsServer.Serve(tlsListener); err != nil {
			t.Logf("failed to run the test server: %v", err)
		}
	}()
	defer tlsServer.Close()

	tmpDir := t.TempDir()
	clientCertPath := filepath.Join(tmpDir, "client.crt")
	clientKeyPath := filepath.Join(tmpDir, "client.key")

	if err := certutil.WriteCert(clientCertPath, clientCert); err != nil {
		t.Fatalf("failed to write client cert: %v", err)
	}
	if err := keyutil.WriteKey(clientKeyPath, clientKey); err != nil {
		t.Fatalf("failed to write client key: %v", err)
	}

	serverCA := x509.NewCertPool()
	serverCA.AppendCertsFromPEM(cert)
	roundTripper, err := initTransport(serverCA, clientCertPath, clientKeyPath, 0)
	if err != nil {
		t.Errorf("want err to be nil, but got %v", err)
		return
	}

	httpReq, err := http.NewRequest(http.MethodPost, fmt.Sprintf("https://127.0.0.1:%d", l.Addr().(*net.TCPAddr).Port), nil)
	if err != nil {
		t.Fatalf("failed to create an HTTP request: %v", err)
	}

	resp, err := roundTripper.RoundTrip(httpReq)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Logf("failed to read response body: %v", err)
		}
		t.Logf("response with failure logs:\n%s", respBody)
		t.Errorf("expected the response code to be '%d', but it is '%d'", http.StatusOK, resp.StatusCode)
	}
}

func generateClientCert(t *testing.T) ([]byte, []byte, *x509.CertPool, error) {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate private key: %v", err)
	}
	ca, err := certutil.NewSelfSignedCACert(certutil.Config{CommonName: "testing-ca"}, privKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate CA cert: %v", err)
	}

	privKeyClient, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	certDER, err := x509.CreateCertificate(rand.Reader,
		&x509.Certificate{
			Subject:      pkix.Name{CommonName: "testing-client"},
			SerialNumber: big.NewInt(15233),
			NotBefore:    time.Now().Add(-5 * time.Second),
			NotAfter:     time.Now().Add(1 * time.Minute),
			KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
		ca, privKeyClient.Public(), privKey,
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create a client cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	caPool := x509.NewCertPool()
	caPool.AddCert(ca)

	privKeyPEM, err := keyutil.MarshalPrivateKeyToPEM(privKeyClient)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to encode private key to pem: %v", err)
	}

	return certPEM, privKeyPEM, caPool, nil
}
