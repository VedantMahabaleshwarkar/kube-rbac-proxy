/*
Copyright 2026 the kube-rbac-proxy maintainers. All rights reserved.

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

package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/felixge/httpsnoop"
	"github.com/google/go-cmp/cmp"

	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	requestcontext "k8s.io/apiserver/pkg/endpoints/request"

	"github.com/brancz/kube-rbac-proxy/pkg/authz"
)

func TestEventContract(t *testing.T) {
	upstream, err := url.Parse("https://[2001:db8::20]:9443")
	if err != nil {
		t.Fatal(err)
	}
	logger := NewLogger(io.Discard, Options{
		Resource: ResourceMetadata{
			Name:      "fraud-detector",
			Namespace: "models",
		},
		UseForwardedFor: true,
		UpstreamURL:     upstream,
		ProductVersion:  "v0.21.0",
	})
	t.Cleanup(logger.Close)
	req := httptest.NewRequest(http.MethodPost, "https://proxy.example/v1/models/fraud:predict?tenant=private", strings.NewReader("prompt-secret"))
	req.Proto = "HTTP/2.0"
	req.RemoteAddr = "192.0.2.10:43120"
	req.Header.Add("X-Forwarded-For", "198.51.100.4, invalid")
	req.Header.Add("X-Forwarded-For", "2001:db8::5")

	started := time.Unix(1_700_000_000, 123_000_000)
	logged := started.Add(1500 * time.Millisecond)
	principal := &user.DefaultInfo{
		Name:   "system:serviceaccount:models:client",
		UID:    "uid-123",
		Groups: []string{"system:serviceaccounts", "models-readers"},
	}
	got := logger.event(req, &requestContext{user: principal}, httpsnoop.Metrics{
		Code:     http.StatusCreated,
		Duration: 1500 * time.Millisecond,
		Written:  27,
	}, started)
	got.Metadata.LoggedTime = logged.UnixMilli()

	want := Event{
		ActivityID:   99,
		ActivityName: "Inference",
		CategoryUID:  6,
		CategoryName: "Application Activity",
		ClassUID:     6003,
		ClassName:    "API Activity",
		TypeUID:      600399,
		SeverityID:   1,
		Severity:     "Informational",
		Time:         started.UnixMilli(),
		Metadata: Metadata{
			Version:  "1.9.0",
			Profiles: []string{"ai_operation"},
			Product: Product{
				Name:    "kube-rbac-proxy",
				Version: "v0.21.0",
			},
			LoggedTime: logged.UnixMilli(),
		},
		Actor: Actor{User: User{
			Name:   "system:serviceaccount:models:client",
			UID:    "uid-123",
			TypeID: 4,
			Groups: []Group{{Name: "system:serviceaccounts"}, {Name: "models-readers"}},
		}},
		API: API{Operation: "POST /v1/models/fraud:predict"},
		HTTPRequest: HTTPRequest{
			HTTPMethod:    "POST",
			Version:       "2.0",
			URL:           URL{Path: "/v1/models/fraud:predict"},
			XForwardedFor: []string{"198.51.100.4", "2001:db8::5"},
		},
		HTTPResponse: HTTPResponse{Code: 201, BodyLength: 27, Latency: 1500},
		SrcEndpoint:  Endpoint{IP: "2001:db8::5"},
		DstEndpoint:  &Endpoint{IP: "2001:db8::20", Port: 9443},
		StatusID:     1,
		Status:       "Success",
		StatusCode:   "201",
		Resources: []Resource{{
			Name:      "fraud-detector",
			Namespace: "models",
			Type:      "InferenceService",
			RoleID:    1,
			Role:      "Target",
		}},
		AIModel: &AIModel{Name: "fraud-detector", AIProvider: "KServe"},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("event mismatch (-want +got):\n%s", diff)
	}

	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"activity_id", "category_uid", "class_uid", "type_uid", "severity_id", "time", "status_id"} {
		if _, ok := document[field].(float64); !ok {
			t.Errorf("%s has JSON type %T, want number", field, document[field])
		}
	}
	if _, ok := document["status_code"].(string); !ok {
		t.Errorf("status_code has JSON type %T, want string", document["status_code"])
	}

	golden, err := os.ReadFile("testdata/inference-success.json")
	if err != nil {
		t.Fatal(err)
	}
	var compactGolden bytes.Buffer
	if err := json.Compact(&compactGolden, golden); err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(compactGolden.String(), string(encoded)); diff != "" {
		t.Errorf("golden event mismatch (-want +got):\n%s", diff)
	}
}

func TestMiddlewareStatusIdentityAndStreaming(t *testing.T) {
	tests := []struct {
		name          string
		statusCode    int
		body          string
		principal     user.Info
		implicit      bool
		stream        bool
		informational bool
		wantUser      string
		wantStatus    string
	}{
		{name: "successful inference", statusCode: 201, body: "created", principal: &user.DefaultInfo{Name: "alice"}, wantUser: "alice", wantStatus: "Success"},
		{name: "unauthenticated", statusCode: 401, body: "Unauthorized\n", wantUser: "Unknown", wantStatus: "Failure"},
		{name: "authorized user forbidden", statusCode: 403, body: "Forbidden\n", principal: &user.DefaultInfo{Name: "bob", UID: "42"}, wantUser: "bob", wantStatus: "Failure"},
		{name: "malformed request", statusCode: 400, body: "Bad Request\n", principal: &user.DefaultInfo{Name: "carol"}, wantUser: "carol", wantStatus: "Failure"},
		{name: "upstream server failure", statusCode: 500, body: "failure", principal: &user.DefaultInfo{Name: "dave"}, wantUser: "dave", wantStatus: "Failure"},
		{name: "upstream proxy failure", statusCode: 502, body: "bad gateway", principal: &user.DefaultInfo{Name: "erin"}, wantUser: "erin", wantStatus: "Failure"},
		{name: "implicit success", body: "ok", principal: &user.DefaultInfo{Name: "frank"}, implicit: true, wantUser: "frank", wantStatus: "Success"},
		{name: "streaming success", body: "chunk-onechunk-two", principal: &user.DefaultInfo{Name: "grace"}, implicit: true, stream: true, wantUser: "grace", wantStatus: "Success"},
		{name: "informational response is not final", statusCode: 201, principal: &user.DefaultInfo{Name: "heidi"}, informational: true, wantUser: "heidi", wantStatus: "Success"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			logger := NewLogger(&output, Options{ProductVersion: "test"})
			endpoint := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tt.informational {
					w.WriteHeader(http.StatusEarlyHints)
				}
				if !tt.implicit {
					w.WriteHeader(tt.statusCode)
				}
				if tt.stream {
					flusher, ok := w.(http.Flusher)
					if !ok {
						t.Fatal("audit response writer does not preserve http.Flusher")
					}
					_, _ = io.WriteString(w, "chunk-one")
					flusher.Flush()
					_, _ = io.WriteString(w, "chunk-two")
					return
				}
				_, _ = io.WriteString(w, tt.body)
			})

			handler := endpoint
			if tt.principal != nil {
				handler = logger.CaptureUser(handler)
				capture := handler
				handler = func(w http.ResponseWriter, req *http.Request) {
					capture(w, req.WithContext(requestcontext.WithUser(req.Context(), tt.principal)))
				}
			}
			handler = logger.WithAuditLog(handler)

			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "http://proxy/v1/models/model:predict", nil)
			req.RemoteAddr = "192.0.2.1:1234"
			handler(recorder, req)
			logger.Close()

			var event Event
			if err := json.NewDecoder(&output).Decode(&event); err != nil {
				t.Fatalf("decode audit event: %v", err)
			}
			wantCode := tt.statusCode
			if tt.implicit {
				wantCode = http.StatusOK
			}
			if event.HTTPResponse.Code != wantCode {
				t.Errorf("response code = %d, want %d", event.HTTPResponse.Code, wantCode)
			}
			if event.HTTPResponse.BodyLength != int64(len(tt.body)) {
				t.Errorf("body length = %d, want %d", event.HTTPResponse.BodyLength, len(tt.body))
			}
			if event.Actor.User.Name != tt.wantUser {
				t.Errorf("actor user = %q, want %q", event.Actor.User.Name, tt.wantUser)
			}
			if event.Status != tt.wantStatus {
				t.Errorf("status = %q, want %q", event.Status, tt.wantStatus)
			}
		})
	}
}

func TestSensitiveValuesAreNotLogged(t *testing.T) {
	var output bytes.Buffer
	logger := NewLogger(&output, Options{
		Resource:       ResourceMetadata{Name: "safe-model"},
		ProductVersion: "test",
	})
	endpoint := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "response-secret")
	})
	handler := logger.WithAuditLog(endpoint)
	req := httptest.NewRequest(http.MethodPost, "http://proxy/infer?query-secret=value", strings.NewReader("prompt-secret"))
	req.RemoteAddr = "192.0.2.2:8080"
	req.Header.Set("Authorization", "Bearer bearer-secret")
	req.Header.Set("Cookie", "session=cookie-secret")
	req.Header.Set("X-Custom-Secret", "header-secret")
	handler(httptest.NewRecorder(), req)
	logger.Close()

	logLine := output.String()
	for _, secret := range []string{"query-secret", "prompt-secret", "response-secret", "bearer-secret", "cookie-secret", "header-secret"} {
		if strings.Contains(logLine, secret) {
			t.Errorf("audit output contains sensitive value %q: %s", secret, logLine)
		}
	}
	for _, forbiddenField := range []string{"authorization", "cookie", "http_headers", "message_context", "prompt_tokens", "completion_tokens", "total_tokens"} {
		if strings.Contains(strings.ToLower(logLine), forbiddenField) {
			t.Errorf("audit output contains forbidden field %q: %s", forbiddenField, logLine)
		}
	}
}

func TestUnavailableOptionalFieldsAreOmitted(t *testing.T) {
	logger := NewLogger(io.Discard, Options{ProductVersion: "test"})
	t.Cleanup(logger.Close)
	req := httptest.NewRequest(http.MethodGet, "http://proxy/infer", nil)
	req.RemoteAddr = "not-an-address"
	event := logger.event(req, &requestContext{}, httpsnoop.Metrics{Code: 401}, time.Unix(1, 0))
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"resources", "ai_model", "dst_endpoint"} {
		if _, ok := document[field]; ok {
			t.Errorf("optional field %q must be omitted: %s", field, encoded)
		}
	}
	if diff := cmp.Diff(Endpoint{Name: "Unknown"}, event.SrcEndpoint); diff != "" {
		t.Errorf("unknown source endpoint mismatch (-want +got):\n%s", diff)
	}
}

func TestConcurrentJSONLinesDoNotInterleave(t *testing.T) {
	const requests = 100
	var output bytes.Buffer
	logger := NewLogger(&output, Options{ProductVersion: "test"})
	handler := logger.WithAuditLog(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})

	var wg sync.WaitGroup
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("http://proxy/infer/%d", i), nil)
			req.RemoteAddr = "192.0.2.3:8080"
			handler(httptest.NewRecorder(), req)
		}(i)
	}
	wg.Wait()
	logger.Close()

	decoder := json.NewDecoder(&output)
	count := 0
	for {
		var event Event
		err := decoder.Decode(&event)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("decode event %d: %v", count, err)
		}
		count++
	}
	if count != requests {
		t.Fatalf("decoded %d events, want %d", count, requests)
	}
}

func TestOversizedAuditEventIsDroppedBeforeQueueing(t *testing.T) {
	var output bytes.Buffer
	logger := NewLogger(&output, Options{ProductVersion: "test"})
	handler := logger.WithAuditLog(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	oversizedPath := "/" + strings.Repeat("a", 128<<10)
	oversizedReq := httptest.NewRequest(http.MethodPost, "http://proxy"+oversizedPath, nil)
	oversizedReq.RemoteAddr = "192.0.2.3:8080"
	handler(httptest.NewRecorder(), oversizedReq)

	normalReq := httptest.NewRequest(http.MethodPost, "http://proxy/infer", nil)
	normalReq.RemoteAddr = "192.0.2.3:8080"
	handler(httptest.NewRecorder(), normalReq)
	logger.Close()

	if got := logger.dropped.Load(); got != 1 {
		t.Fatalf("dropped events = %d, want 1", got)
	}
	decoder := json.NewDecoder(&output)
	var event Event
	if err := decoder.Decode(&event); err != nil {
		t.Fatalf("decode retained audit event: %v", err)
	}
	if event.HTTPRequest.URL.Path != "/infer" {
		t.Errorf("retained audit path = %q, want /infer", event.HTTPRequest.URL.Path)
	}
	if err := decoder.Decode(&Event{}); err != io.EOF {
		t.Fatalf("expected exactly one retained audit event, got trailing decode error %v", err)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("audit sink failed")
}

func TestAuditWriteFailureDoesNotChangeResponse(t *testing.T) {
	logger := NewLogger(failingWriter{}, Options{ProductVersion: "test"})
	handler := logger.WithAuditLog(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, "accepted")
	})
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://proxy/infer", nil)
	req.RemoteAddr = "192.0.2.4:8080"
	handler(recorder, req)
	logger.Close()

	if recorder.Code != http.StatusAccepted || recorder.Body.String() != "accepted" {
		t.Fatalf("response changed after audit failure: code=%d body=%q", recorder.Code, recorder.Body.String())
	}
}

func TestPanickingHandlerIsAuditedAndPanicPropagates(t *testing.T) {
	var output bytes.Buffer
	logger := NewLogger(&output, Options{ProductVersion: "test"})
	handler := logger.WithAuditLog(func(http.ResponseWriter, *http.Request) {
		panic("handler failed")
	})
	req := httptest.NewRequest(http.MethodPost, "http://proxy/infer", nil)
	req.RemoteAddr = "192.0.2.5:8080"

	var recovered any
	func() {
		defer func() { recovered = recover() }()
		handler(httptest.NewRecorder(), req)
	}()
	logger.Close()

	if recovered != "handler failed" {
		t.Fatalf("recovered panic = %v, want handler failed", recovered)
	}
	var event Event
	if err := json.NewDecoder(&output).Decode(&event); err != nil {
		t.Fatalf("decode audit event: %v", err)
	}
	if event.HTTPResponse.Code != http.StatusInternalServerError || event.Status != "Failure" {
		t.Fatalf("panic event status = %d/%s, want 500/Failure", event.HTTPResponse.Code, event.Status)
	}
}

func TestPanickingHandlerPreservesCommittedResponseCode(t *testing.T) {
	var output bytes.Buffer
	logger := NewLogger(&output, Options{ProductVersion: "test"})
	handler := logger.WithAuditLog(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		panic("handler failed after response")
	})
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://proxy/infer", nil)
	req.RemoteAddr = "192.0.2.5:8080"

	var recovered any
	func() {
		defer func() { recovered = recover() }()
		handler(recorder, req)
	}()
	logger.Close()

	if recovered != "handler failed after response" {
		t.Fatalf("recovered panic = %v, want handler failed after response", recovered)
	}
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("committed response code = %d, want %d", recorder.Code, http.StatusAccepted)
	}
	var event Event
	if err := json.NewDecoder(&output).Decode(&event); err != nil {
		t.Fatalf("decode audit event: %v", err)
	}
	if event.HTTPResponse.Code != http.StatusAccepted {
		t.Errorf("audit response code = %d, want %d", event.HTTPResponse.Code, http.StatusAccepted)
	}
	if event.Status != "Failure" || event.StatusID != 2 {
		t.Errorf("audit outcome = %q/%d, want Failure/2", event.Status, event.StatusID)
	}
	if event.StatusCode != "202" {
		t.Errorf("audit status code = %q, want 202", event.StatusCode)
	}
}

func TestPanickingHandlerPreservesImplicitResponseCodeAfterEmptyWrite(t *testing.T) {
	var output bytes.Buffer
	logger := NewLogger(&output, Options{ProductVersion: "test"})
	handler := logger.WithAuditLog(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write(nil); err != nil {
			t.Fatalf("write empty response: %v", err)
		}
		panic("handler failed after empty write")
	})
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://proxy/infer", nil)
	req.RemoteAddr = "192.0.2.5:8080"

	var recovered any
	func() {
		defer func() { recovered = recover() }()
		handler(recorder, req)
	}()
	logger.Close()

	if recovered != "handler failed after empty write" {
		t.Fatalf("recovered panic = %v, want handler failed after empty write", recovered)
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("committed response code = %d, want %d", recorder.Code, http.StatusOK)
	}
	var event Event
	if err := json.NewDecoder(&output).Decode(&event); err != nil {
		t.Fatalf("decode audit event: %v", err)
	}
	if event.HTTPResponse.Code != http.StatusOK {
		t.Errorf("audit response code = %d, want %d", event.HTTPResponse.Code, http.StatusOK)
	}
	if event.Status != "Failure" || event.StatusID != statusFailureID {
		t.Errorf("audit outcome = %q/%d, want Failure/%d", event.Status, event.StatusID, statusFailureID)
	}
	if event.StatusCode != "200" {
		t.Errorf("audit status code = %q, want 200", event.StatusCode)
	}
}

func TestRequestSpecificResourceMetadata(t *testing.T) {
	var output bytes.Buffer
	logger := NewLogger(&output, Options{
		Resource:              ResourceMetadata{Namespace: "flag-namespace"},
		AuthorizationResource: ResourceMetadata{Name: "static-name", Namespace: "static-namespace"},
		ProductVersion:        "test",
	})
	handler := logger.WithAuditLog(func(w http.ResponseWriter, req *http.Request) {
		logger.CaptureAuthorizationAttributes(req, []authorizer.Attributes{authorizer.AttributesRecord{
			Name:            "request-model",
			Namespace:       "request-namespace",
			ResourceRequest: true,
		}})
		w.WriteHeader(http.StatusForbidden)
	})
	req := httptest.NewRequest(http.MethodPost, "http://proxy/infer", nil)
	req.RemoteAddr = "192.0.2.6:8080"
	handler(httptest.NewRecorder(), req)
	logger.Close()

	var event Event
	if err := json.NewDecoder(&output).Decode(&event); err != nil {
		t.Fatalf("decode audit event: %v", err)
	}
	want := []Resource{{
		Name:      "request-model",
		Namespace: "flag-namespace",
		Type:      "InferenceService",
		RoleID:    resourceRoleTargetID,
		Role:      resourceRoleTargetName,
	}}
	if diff := cmp.Diff(want, event.Resources); diff != "" {
		t.Errorf("resource metadata mismatch (-want +got):\n%s", diff)
	}
}

type blockingWriter struct {
	started     chan struct{}
	release     chan struct{}
	startedOnce sync.Once
	buffer      bytes.Buffer
}

func (w *blockingWriter) Write(p []byte) (int, error) {
	w.startedOnce.Do(func() { close(w.started) })
	<-w.release
	return w.buffer.Write(p)
}

func (w *blockingWriter) Bytes() []byte {
	return w.buffer.Bytes()
}

func TestSlowWriterDoesNotBlockRequestHandlers(t *testing.T) {
	writer := &blockingWriter{started: make(chan struct{}), release: make(chan struct{})}
	logger := newLogger(writer, Options{ProductVersion: "test"}, 1)
	handler := logger.WithAuditLog(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	request := func() {
		req := httptest.NewRequest(http.MethodPost, "http://proxy/infer", nil)
		req.RemoteAddr = "192.0.2.7:8080"
		handler(httptest.NewRecorder(), req)
	}

	request()
	select {
	case <-writer.started:
	case <-time.After(time.Second):
		t.Fatal("audit writer did not receive the first event")
	}
	request()
	done := make(chan struct{})
	go func() {
		request()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("request blocked on a saturated audit queue")
	}
	if got := logger.dropped.Load(); got != 1 {
		t.Fatalf("dropped events = %d, want 1", got)
	}

	close(writer.release)
	logger.Close()
}

func TestLoggedTimeIsAssignedAtWriterBoundary(t *testing.T) {
	writer := &blockingWriter{started: make(chan struct{}), release: make(chan struct{})}
	logger := newLogger(writer, Options{ProductVersion: "test"}, 1)
	released := false
	t.Cleanup(func() {
		if !released {
			close(writer.release)
		}
		logger.Close()
	})
	handler := logger.WithAuditLog(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	request := func(path string) {
		req := httptest.NewRequest(http.MethodPost, "http://proxy"+path, nil)
		req.RemoteAddr = "192.0.2.8:8080"
		handler(httptest.NewRecorder(), req)
	}

	request("/first")
	select {
	case <-writer.started:
	case <-time.After(time.Second):
		t.Fatal("audit writer did not block on the first event")
	}
	request("/second")
	time.Sleep(20 * time.Millisecond)
	writerBoundary := time.Now().UnixMilli()
	close(writer.release)
	released = true
	logger.Close()

	decoder := json.NewDecoder(bytes.NewReader(writer.Bytes()))
	var first, second Event
	if err := decoder.Decode(&first); err != nil {
		t.Fatalf("decode first audit event: %v", err)
	}
	if err := decoder.Decode(&second); err != nil {
		t.Fatalf("decode second audit event: %v", err)
	}
	if second.HTTPRequest.URL.Path != "/second" {
		t.Fatalf("second audit path = %q, want /second", second.HTTPRequest.URL.Path)
	}
	if second.Metadata.LoggedTime < writerBoundary {
		t.Errorf("second logged_time = %d, want >= writer boundary %d", second.Metadata.LoggedTime, writerBoundary)
	}
}

func TestResolveResourceMetadata(t *testing.T) {
	attrs := &authz.ResourceAttributes{Name: "config-name", Namespace: "config-namespace"}
	tests := []struct {
		name     string
		explicit ResourceMetadata
		attrs    *authz.ResourceAttributes
		want     ResourceMetadata
	}{
		{name: "explicit values take precedence", explicit: ResourceMetadata{Name: "flag-name", Namespace: "flag-namespace"}, attrs: attrs, want: ResourceMetadata{Name: "flag-name", Namespace: "flag-namespace"}},
		{name: "each missing value falls back independently", explicit: ResourceMetadata{Name: "flag-name"}, attrs: attrs, want: ResourceMetadata{Name: "flag-name", Namespace: "config-namespace"}},
		{name: "authorization attributes are fallback", attrs: attrs, want: ResourceMetadata{Name: "config-name", Namespace: "config-namespace"}},
		{name: "authorization templates are unavailable until request resolution", attrs: &authz.ResourceAttributes{Name: "{{.Name}}", Namespace: "{{.Namespace}}"}, want: ResourceMetadata{}},
		{name: "missing metadata is allowed", want: ResourceMetadata{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveResourceMetadata(tt.explicit.Name, tt.explicit.Namespace, tt.attrs)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("metadata mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
