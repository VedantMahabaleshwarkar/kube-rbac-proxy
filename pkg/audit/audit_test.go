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
	"context"
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
	"unicode/utf8"

	"github.com/felixge/httpsnoop"
	"github.com/google/go-cmp/cmp"

	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	requestcontext "k8s.io/apiserver/pkg/endpoints/request"

	"github.com/brancz/kube-rbac-proxy/pkg/authz"
)

func closeLogger(t *testing.T, logger *Logger) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := logger.Close(ctx); err != nil {
		t.Fatalf("close audit logger: %v", err)
	}
}

func TestEventContract(t *testing.T) {
	upstream, err := url.Parse("https://[2001:db8::20]:9443")
	if err != nil {
		t.Fatal(err)
	}
	logger := NewLogger(io.Discard, Options{
		Resource: ResourceMetadata{
			Name:      "fraud-detector",
			Namespace: "models",
			Type:      "InferenceService",
		},
		AIProvider:      "KServe",
		UseForwardedFor: true,
		UpstreamURL:     upstream,
		ProductVersion:  "v0.21.0",
	})
	t.Cleanup(func() { closeLogger(t, logger) })
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

func TestAuditGapEventContract(t *testing.T) {
	event := newGapEvent(lossSnapshot{
		Count:     3,
		StartTime: 1_700_000_000_000,
		EndTime:   1_700_000_000_250,
	}, "v0.21.0", 1_700_000_000_500)
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}

	golden, err := os.ReadFile("testdata/audit-gap.json")
	if err != nil {
		t.Fatal(err)
	}
	var compactGolden bytes.Buffer
	if err := json.Compact(&compactGolden, golden); err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(compactGolden.String(), string(encoded)); diff != "" {
		t.Errorf("golden gap event mismatch (-want +got):\n%s", diff)
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
			closeLogger(t, logger)

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
	closeLogger(t, logger)

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
	t.Cleanup(func() { closeLogger(t, logger) })
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
	closeLogger(t, logger)

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

func TestOversizedAuditEventIsEmittedAsBoundedFallback(t *testing.T) {
	var output bytes.Buffer
	upstream, err := url.Parse("https://192.0.2.200:9443")
	if err != nil {
		t.Fatal(err)
	}
	logger := NewLogger(&output, Options{
		Resource:       ResourceMetadata{Name: "fraud-detector", Namespace: "models", Type: "InferenceService"},
		AIProvider:     "KServe",
		UpstreamURL:    upstream,
		ProductVersion: "test",
	})

	oversizedPath := "/" + strings.Repeat("\u00e9\\\"", 32<<10)
	target := (&url.URL{Scheme: "http", Host: "proxy", Path: oversizedPath}).String()
	req := httptest.NewRequest(http.MethodPost, target, nil)
	req.Proto = "HTTP/2.0"
	req.RemoteAddr = "192.0.2.3:8080"
	event := logger.event(req, &requestContext{user: &user.DefaultInfo{
		Name:   "system:serviceaccount:models:client",
		UID:    "uid-123",
		Groups: []string{"system:serviceaccounts", "models-readers"},
	}}, httpsnoop.Metrics{
		Code:     http.StatusForbidden,
		Duration: 1500 * time.Millisecond,
		Written:  27,
	}, time.Unix(1_700_000_000, 123_000_000))
	event.HTTPRequest.XForwardedFor = []string{"198.51.100.4", "2001:db8::5"}
	fullPayload, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if len(fullPayload) <= maxAuditEventSize {
		t.Fatalf("full audit payload size = %d, want > %d", len(fullPayload), maxAuditEventSize)
	}

	logger.enqueue(event)
	closeLogger(t, logger)

	if got := logger.dropped.Load(); got != 0 {
		t.Fatalf("dropped events = %d, want 0", got)
	}
	payload := bytes.TrimSuffix(output.Bytes(), []byte("\n"))
	if len(payload) > maxAuditEventSize {
		t.Fatalf("bounded audit payload size = %d, want <= %d", len(payload), maxAuditEventSize)
	}
	if !utf8.Valid(payload) {
		t.Fatal("bounded audit payload is not valid UTF-8")
	}
	var document struct {
		Metadata map[string]any `json:"metadata"`
		Unmapped map[string]any `json:"unmapped"`
	}
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatalf("decode bounded audit document: %v", err)
	}
	if truncated, ok := document.Metadata["is_truncated"].(bool); !ok || !truncated {
		t.Errorf("metadata.is_truncated = %#v, want true", document.Metadata["is_truncated"])
	}
	if originalSize, ok := document.Metadata["untruncated_size"].(float64); !ok || int(originalSize) != len(fullPayload) {
		t.Errorf("metadata.untruncated_size = %#v, want %d", document.Metadata["untruncated_size"], len(fullPayload))
	}
	if document.Unmapped != nil {
		t.Errorf("bounded audit unmapped data = %#v, want omitted", document.Unmapped)
	}

	decoder := json.NewDecoder(&output)
	var got Event
	if err := decoder.Decode(&got); err != nil {
		t.Fatalf("decode bounded audit event: %v", err)
	}
	if err := decoder.Decode(&Event{}); err != io.EOF {
		t.Fatalf("expected exactly one bounded audit event, got trailing decode error %v", err)
	}

	if got.ClassUID != classUID || got.ClassName != className || got.Time != event.Time {
		t.Errorf("classification/time not preserved: class=%d/%q time=%d", got.ClassUID, got.ClassName, got.Time)
	}
	wantUser := User{Name: "system:serviceaccount:models:client", UID: "uid-123", TypeID: 4}
	if diff := cmp.Diff(wantUser, got.Actor.User); diff != "" {
		t.Errorf("bounded user mismatch (-want +got):\n%s", diff)
	}
	wantResources := []Resource{{Name: "fraud-detector", Namespace: "models", Type: "InferenceService", RoleID: 1, Role: "Target"}}
	if diff := cmp.Diff(wantResources, got.Resources); diff != "" {
		t.Errorf("bounded resources mismatch (-want +got):\n%s", diff)
	}
	if got.HTTPRequest.HTTPMethod != http.MethodPost || got.HTTPRequest.Version != "2.0" {
		t.Errorf("bounded HTTP method/version = %q/%q, want POST/2.0", got.HTTPRequest.HTTPMethod, got.HTTPRequest.Version)
	}
	if got.SrcEndpoint.IP != "192.0.2.3" || got.SrcEndpoint.Port != 8080 {
		t.Errorf("bounded source endpoint = %+v, want 192.0.2.3:8080", got.SrcEndpoint)
	}
	if diff := cmp.Diff(event.HTTPResponse, got.HTTPResponse); diff != "" {
		t.Errorf("bounded response metrics mismatch (-want +got):\n%s", diff)
	}
	if got.StatusID != statusFailureID || got.Status != statusFailureName || got.StatusCode != "403" {
		t.Errorf("bounded outcome = %d/%q/%q, want 2/Failure/403", got.StatusID, got.Status, got.StatusCode)
	}
	if len(got.HTTPRequest.URL.Path) > 1024 || !utf8.ValidString(got.HTTPRequest.URL.Path) || !strings.HasSuffix(got.HTTPRequest.URL.Path, "[truncated]") {
		t.Errorf("bounded path is not a valid marked 1024-byte value: bytes=%d suffix=%t", len(got.HTTPRequest.URL.Path), strings.HasSuffix(got.HTTPRequest.URL.Path, "[truncated]"))
	}
	if len(got.API.Operation) > 256 || !utf8.ValidString(got.API.Operation) || !strings.HasSuffix(got.API.Operation, "[truncated]") {
		t.Errorf("bounded operation is not a valid marked 256-byte value: bytes=%d suffix=%t", len(got.API.Operation), strings.HasSuffix(got.API.Operation, "[truncated]"))
	}
	if got.Actor.User.Groups != nil || got.HTTPRequest.XForwardedFor != nil {
		t.Errorf("high-cardinality fallback fields were retained: groups=%v forwarded=%v", got.Actor.User.Groups, got.HTTPRequest.XForwardedFor)
	}
	wantDstEndpoint := &Endpoint{IP: "192.0.2.200", Port: 9443}
	if diff := cmp.Diff(wantDstEndpoint, got.DstEndpoint); diff != "" {
		t.Errorf("bounded destination endpoint mismatch (-want +got):\n%s", diff)
	}
	wantAIModel := &AIModel{Name: "fraud-detector", AIProvider: "KServe"}
	if diff := cmp.Diff(wantAIModel, got.AIModel); diff != "" {
		t.Errorf("bounded AI model mismatch (-want +got):\n%s", diff)
	}
}

func TestTruncateUTF8KeepsMarkerWithinByteLimit(t *testing.T) {
	tests := []struct {
		name  string
		value string
		limit int
	}{
		{name: "multibyte path", value: strings.Repeat("\u00e9", 600), limit: 1024},
		{name: "JSON escaping", value: strings.Repeat("\\\"", 200), limit: 256},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateUTF8(tt.value, tt.limit)
			if len(got) > tt.limit {
				t.Fatalf("truncated bytes = %d, want <= %d", len(got), tt.limit)
			}
			if !utf8.ValidString(got) {
				t.Fatalf("truncated value is not valid UTF-8: %q", got)
			}
			if !strings.HasSuffix(got, "[truncated]") {
				t.Fatalf("truncated value %q does not contain the marker within its limit", got)
			}
			prefix := strings.TrimSuffix(got, "[truncated]")
			if !strings.HasPrefix(tt.value, prefix) {
				t.Fatalf("truncated prefix %q is not a prefix of the input", prefix)
			}
			encoded, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("marshal truncated value: %v", err)
			}
			var roundTrip string
			if err := json.Unmarshal(encoded, &roundTrip); err != nil {
				t.Fatalf("unmarshal truncated value: %v", err)
			}
			if roundTrip != got {
				t.Fatalf("JSON round trip = %q, want %q", roundTrip, got)
			}
		})
	}
}

func TestBoundedAuditEventCapsEveryRetainedDynamicString(t *testing.T) {
	longDynamic := strings.Repeat("\u00e9\\\"", 300)
	longPath := "/" + strings.Repeat("\u00e9\\\"", 600)
	event := Event{
		ActivityName: longDynamic,
		CategoryName: longDynamic,
		ClassName:    longDynamic,
		Severity:     longDynamic,
		Metadata: Metadata{
			Version:  longDynamic,
			Profiles: []string{longDynamic},
			Product:  Product{Name: longDynamic, Version: longDynamic},
		},
		Actor: Actor{User: User{Name: longDynamic, UID: longDynamic, Groups: []Group{{Name: longDynamic}}}},
		API:   API{Operation: longDynamic},
		HTTPRequest: HTTPRequest{
			HTTPMethod:    longDynamic,
			Version:       longDynamic,
			URL:           URL{Path: longPath},
			XForwardedFor: []string{longDynamic},
		},
		SrcEndpoint: Endpoint{Name: longDynamic, Hostname: longDynamic, IP: longDynamic},
		DstEndpoint: &Endpoint{Name: longDynamic, Hostname: longDynamic, IP: longDynamic},
		Status:      longDynamic,
		StatusCode:  longDynamic,
		Resources: []Resource{{
			Name: longDynamic, Namespace: longDynamic, Type: longDynamic, Role: longDynamic,
		}},
		AIModel: &AIModel{Name: longDynamic, AIProvider: longDynamic},
	}

	got := boundedAuditEvent(event, 128<<10)
	if diff := cmp.Diff([]string{aiOperationProfile}, got.Metadata.Profiles); diff != "" {
		t.Errorf("bounded profiles mismatch (-want +got):\n%s", diff)
	}
	if got.Actor.User.Groups != nil || got.HTTPRequest.XForwardedFor != nil {
		t.Errorf("fallback-only omissions were retained: groups=%v forwarded=%v", got.Actor.User.Groups, got.HTTPRequest.XForwardedFor)
	}
	if got.DstEndpoint == nil {
		t.Fatal("bounded destination endpoint is nil")
	}
	if got.AIModel == nil {
		t.Fatal("bounded AI model is nil")
	}
	retained := map[string]string{
		"activity_name":      got.ActivityName,
		"category_name":      got.CategoryName,
		"class_name":         got.ClassName,
		"severity":           got.Severity,
		"metadata.version":   got.Metadata.Version,
		"product.name":       got.Metadata.Product.Name,
		"product.version":    got.Metadata.Product.Version,
		"user.name":          got.Actor.User.Name,
		"user.uid":           got.Actor.User.UID,
		"api.operation":      got.API.Operation,
		"http_method":        got.HTTPRequest.HTTPMethod,
		"http_version":       got.HTTPRequest.Version,
		"src.name":           got.SrcEndpoint.Name,
		"src.hostname":       got.SrcEndpoint.Hostname,
		"src.ip":             got.SrcEndpoint.IP,
		"dst.name":           got.DstEndpoint.Name,
		"dst.hostname":       got.DstEndpoint.Hostname,
		"dst.ip":             got.DstEndpoint.IP,
		"status":             got.Status,
		"status_code":        got.StatusCode,
		"resource.name":      got.Resources[0].Name,
		"resource.namespace": got.Resources[0].Namespace,
		"resource.type":      got.Resources[0].Type,
		"resource.role":      got.Resources[0].Role,
		"ai_model.name":      got.AIModel.Name,
		"ai_model.provider":  got.AIModel.AIProvider,
	}
	for name, value := range retained {
		if len(value) > 256 || !utf8.ValidString(value) || !strings.HasSuffix(value, "[truncated]") {
			t.Errorf("%s is not a valid marked 256-byte value: bytes=%d suffix=%t", name, len(value), strings.HasSuffix(value, "[truncated]"))
		}
	}
	if len(got.HTTPRequest.URL.Path) > 1024 || !utf8.ValidString(got.HTTPRequest.URL.Path) || !strings.HasSuffix(got.HTTPRequest.URL.Path, "[truncated]") {
		t.Errorf("path is not a valid marked 1024-byte value: bytes=%d suffix=%t", len(got.HTTPRequest.URL.Path), strings.HasSuffix(got.HTTPRequest.URL.Path, "[truncated]"))
	}
	payload, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) > maxAuditEventSize {
		t.Fatalf("worst-case bounded payload size = %d, want <= %d", len(payload), maxAuditEventSize)
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
	closeLogger(t, logger)

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
	closeLogger(t, logger)

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
	closeLogger(t, logger)

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
	closeLogger(t, logger)

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
		Resource:              ResourceMetadata{Namespace: "flag-namespace", Type: "InferenceService"},
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
	closeLogger(t, logger)

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

type auditWriteAttempt struct {
	payload []byte
	result  chan error
}

func (a *auditWriteAttempt) finish(err error) {
	a.result <- err
}

type controlledWriter struct {
	attempts  chan *auditWriteAttempt
	abort     chan struct{}
	abortOnce sync.Once
}

func newControlledWriter() *controlledWriter {
	return &controlledWriter{
		attempts: make(chan *auditWriteAttempt, 32),
		abort:    make(chan struct{}),
	}
}

func (w *controlledWriter) Write(p []byte) (int, error) {
	attempt := &auditWriteAttempt{
		payload: append([]byte(nil), p...),
		result:  make(chan error, 1),
	}
	select {
	case w.attempts <- attempt:
	case <-w.abort:
		return len(p), nil
	}
	select {
	case err := <-attempt.result:
		if err != nil {
			return 0, err
		}
		return len(p), nil
	case <-w.abort:
		return len(p), nil
	}
}

func (w *controlledWriter) stop() {
	w.abortOnce.Do(func() { close(w.abort) })
}

func nextAuditWrite(t *testing.T, writer *controlledWriter) *auditWriteAttempt {
	t.Helper()
	select {
	case attempt := <-writer.attempts:
		return attempt
	case <-time.After(time.Second):
		t.Fatal("audit writer did not attempt the expected write")
		return nil
	}
}

type decodedAuditRecord struct {
	ClassUID     int         `json:"class_uid"`
	ActivityName string      `json:"activity_name"`
	Time         int64       `json:"time"`
	StartTime    int64       `json:"start_time"`
	EndTime      int64       `json:"end_time"`
	Duration     int64       `json:"duration"`
	Count        int64       `json:"count"`
	Metadata     Metadata    `json:"metadata"`
	HTTPRequest  HTTPRequest `json:"http_request"`
}

func decodeAuditWrite(t *testing.T, attempt *auditWriteAttempt) decodedAuditRecord {
	t.Helper()
	var record decodedAuditRecord
	if err := json.Unmarshal(attempt.payload, &record); err != nil {
		t.Fatalf("decode audit write: %v", err)
	}
	return record
}

func TestLoggerCloseDrainsQueuedEvents(t *testing.T) {
	var output bytes.Buffer
	logger := newLogger(&output, Options{ProductVersion: "test"}, 4)
	handler := logger.WithAuditLog(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("http://proxy/infer/%d", i), nil)
		req.RemoteAddr = "192.0.2.7:8080"
		handler(httptest.NewRecorder(), req)
	}
	closeLogger(t, logger)

	decoder := json.NewDecoder(&output)
	for i := 0; i < 3; i++ {
		var event Event
		if err := decoder.Decode(&event); err != nil {
			t.Fatalf("decode audit event %d: %v", i, err)
		}
		wantPath := fmt.Sprintf("/infer/%d", i)
		if event.HTTPRequest.URL.Path != wantPath {
			t.Errorf("audit path = %q, want %q", event.HTTPRequest.URL.Path, wantPath)
		}
	}
	if err := decoder.Decode(&Event{}); err != io.EOF {
		t.Fatalf("expected exactly three audit events, got trailing decode error %v", err)
	}
}

func TestLoggerCloseIsSafeWhenRepeatedAndConcurrent(t *testing.T) {
	logger := NewLogger(io.Discard, Options{ProductVersion: "test"})

	const closers = 20
	start := make(chan struct{})
	errs := make(chan error, closers)
	var wg sync.WaitGroup
	for i := 0; i < closers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			errs <- logger.Close(ctx)
		}()
	}
	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Errorf("concurrent Close returned error: %v", err)
		}
	}
	closeLogger(t, logger)
}

func TestLoggerCloseDeadlineCanBeRetried(t *testing.T) {
	writer := &blockingWriter{started: make(chan struct{}), release: make(chan struct{})}
	logger := newLogger(writer, Options{ProductVersion: "test"}, 1)
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(writer.release) }) }
	t.Cleanup(func() {
		release()
		closeLogger(t, logger)
	})

	handler := logger.WithAuditLog(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest(http.MethodPost, "http://proxy/infer", nil)
	req.RemoteAddr = "192.0.2.7:8080"
	handler(httptest.NewRecorder(), req)

	select {
	case <-writer.started:
	case <-time.After(time.Second):
		t.Fatal("audit writer did not receive the event")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	closeResult := make(chan error, 1)
	go func() {
		closeResult <- logger.Close(ctx)
	}()
	select {
	case err := <-closeResult:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Close error = %v, want context deadline exceeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not return while the audit writer remained blocked")
	}

	release()
	closeLogger(t, logger)
}

func TestQueueLossIsAggregatedBetweenNormalEventsWithoutBlockingRequests(t *testing.T) {
	writer := newControlledWriter()
	logger := newLogger(writer, Options{ProductVersion: "test"}, 1)
	t.Cleanup(func() {
		writer.stop()
		closeLogger(t, logger)
	})
	handler := logger.WithAuditLog(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	request := func(path string) {
		req := httptest.NewRequest(http.MethodPost, "http://proxy"+path, nil)
		req.RemoteAddr = "192.0.2.7:8080"
		handler(httptest.NewRecorder(), req)
	}

	request("/first")
	first := nextAuditWrite(t, writer)
	if got := decodeAuditWrite(t, first).HTTPRequest.URL.Path; got != "/first" {
		t.Fatalf("first audit path = %q, want /first", got)
	}
	request("/queued")

	firstLossWindowStart := time.Now().UnixMilli()
	done := make(chan struct{})
	go func() {
		request("/dropped-1")
		request("/dropped-2")
		request("/dropped-3")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("requests blocked on a saturated audit queue")
	}
	firstLossWindowEnd := time.Now().UnixMilli()
	if got := logger.dropped.Load(); got != 3 {
		t.Fatalf("dropped events = %d, want 3", got)
	}
	first.finish(nil)

	firstGapAttempt := nextAuditWrite(t, writer)
	firstGap := decodeAuditWrite(t, firstGapAttempt)
	if firstGap.ClassUID != 0 || firstGap.ActivityName != "Audit Event Loss" || firstGap.Count != 3 {
		t.Fatalf("first gap = class %d activity %q count %d, want Base Event loss count 3", firstGap.ClassUID, firstGap.ActivityName, firstGap.Count)
	}
	if firstGap.Time != firstGap.StartTime || firstGap.Duration != firstGap.EndTime-firstGap.StartTime {
		t.Errorf("first gap time range is inconsistent: time=%d start=%d end=%d duration=%d", firstGap.Time, firstGap.StartTime, firstGap.EndTime, firstGap.Duration)
	}
	if firstGap.StartTime < firstLossWindowStart || firstGap.EndTime > firstLossWindowEnd {
		t.Errorf("first gap window [%d,%d] falls outside request window [%d,%d]", firstGap.StartTime, firstGap.EndTime, firstLossWindowStart, firstLossWindowEnd)
	}
	firstGapAttempt.finish(nil)

	queuedAttempt := nextAuditWrite(t, writer)
	if got := decodeAuditWrite(t, queuedAttempt).HTTPRequest.URL.Path; got != "/queued" {
		t.Fatalf("queued audit path = %q, want /queued", got)
	}

	time.Sleep(2 * time.Millisecond)
	request("/queued-later")
	secondLossWindowStart := time.Now().UnixMilli()
	request("/dropped-later-1")
	request("/dropped-later-2")
	secondLossWindowEnd := time.Now().UnixMilli()
	if got := logger.dropped.Load(); got != 5 {
		t.Fatalf("cumulative dropped events = %d, want 5", got)
	}
	queuedAttempt.finish(nil)

	secondGapAttempt := nextAuditWrite(t, writer)
	secondGap := decodeAuditWrite(t, secondGapAttempt)
	if secondGap.ClassUID != 0 || secondGap.ActivityName != "Audit Event Loss" || secondGap.Count != 2 {
		t.Fatalf("second gap = class %d activity %q count %d, want Base Event loss count 2", secondGap.ClassUID, secondGap.ActivityName, secondGap.Count)
	}
	if secondGap.StartTime < secondLossWindowStart || secondGap.EndTime > secondLossWindowEnd {
		t.Errorf("second gap window [%d,%d] falls outside request window [%d,%d]", secondGap.StartTime, secondGap.EndTime, secondLossWindowStart, secondLossWindowEnd)
	}
	secondGapAttempt.finish(nil)

	laterAttempt := nextAuditWrite(t, writer)
	if got := decodeAuditWrite(t, laterAttempt).HTTPRequest.URL.Path; got != "/queued-later" {
		t.Fatalf("later queued audit path = %q, want /queued-later", got)
	}
	laterAttempt.finish(nil)

	closeLogger(t, logger)
	writer.stop()
}

func TestFailedGapWriteIsRetriedBeforeALaterEventAndAtShutdown(t *testing.T) {
	writer := newControlledWriter()
	logger := newLogger(writer, Options{ProductVersion: "test"}, 1)
	t.Cleanup(func() {
		writer.stop()
		closeLogger(t, logger)
	})
	handler := logger.WithAuditLog(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	request := func(path string) {
		req := httptest.NewRequest(http.MethodPost, "http://proxy"+path, nil)
		req.RemoteAddr = "192.0.2.7:8080"
		handler(httptest.NewRecorder(), req)
	}

	request("/first")
	first := nextAuditWrite(t, writer)
	request("/queued")
	request("/dropped")
	first.finish(nil)

	failedGapAttempt := nextAuditWrite(t, writer)
	failedGap := decodeAuditWrite(t, failedGapAttempt)
	if failedGap.ClassUID != 0 || failedGap.Count != 1 {
		t.Fatalf("failed gap = class %d count %d, want Base Event count 1", failedGap.ClassUID, failedGap.Count)
	}
	failedGapAttempt.finish(errors.New("gap sink failure"))

	queuedAttempt := nextAuditWrite(t, writer)
	if got := decodeAuditWrite(t, queuedAttempt).HTTPRequest.URL.Path; got != "/queued" {
		t.Fatalf("write after failed gap = %q, want queued request before retry", got)
	}
	request("/later")
	queuedAttempt.finish(nil)

	retriedGapAttempt := nextAuditWrite(t, writer)
	retriedGap := decodeAuditWrite(t, retriedGapAttempt)
	if retriedGap.ClassUID != 0 || retriedGap.Count != failedGap.Count || retriedGap.Time != failedGap.Time || retriedGap.StartTime != failedGap.StartTime || retriedGap.EndTime != failedGap.EndTime || retriedGap.Duration != failedGap.Duration {
		t.Fatalf("retried gap did not preserve the failed snapshot: failed=%+v retried=%+v", failedGap, retriedGap)
	}
	retriedGapAttempt.finish(errors.New("gap sink failure again"))

	laterAttempt := nextAuditWrite(t, writer)
	if got := decodeAuditWrite(t, laterAttempt).HTTPRequest.URL.Path; got != "/later" {
		t.Fatalf("write after retried gap = %q, want later request before shutdown retry", got)
	}
	laterAttempt.finish(nil)

	closeResult := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		closeResult <- logger.Close(ctx)
	}()
	finalGapAttempt := nextAuditWrite(t, writer)
	finalGap := decodeAuditWrite(t, finalGapAttempt)
	if finalGap.ClassUID != 0 || finalGap.Count != failedGap.Count || finalGap.Time != failedGap.Time || finalGap.StartTime != failedGap.StartTime || finalGap.EndTime != failedGap.EndTime || finalGap.Duration != failedGap.Duration {
		t.Fatalf("shutdown gap did not preserve the failed snapshot: failed=%+v final=%+v", failedGap, finalGap)
	}
	finalGapAttempt.finish(nil)
	if err := <-closeResult; err != nil {
		t.Fatalf("close audit logger: %v", err)
	}
	if got := logger.dropped.Load(); got != 1 {
		t.Fatalf("dropped events = %d, want 1", got)
	}
	writer.stop()
}

func TestLoggedTimeIsAssignedAtWriterBoundary(t *testing.T) {
	writer := &blockingWriter{started: make(chan struct{}), release: make(chan struct{})}
	logger := newLogger(writer, Options{ProductVersion: "test"}, 1)
	released := false
	t.Cleanup(func() {
		if !released {
			close(writer.release)
		}
		closeLogger(t, logger)
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
	closeLogger(t, logger)

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

func TestStaticResourceMetadata(t *testing.T) {
	tests := []struct {
		name  string
		attrs *authz.ResourceAttributes
		want  ResourceMetadata
	}{
		{name: "nil attributes", want: ResourceMetadata{}},
		{name: "static values", attrs: &authz.ResourceAttributes{Name: "config-name", Namespace: "config-namespace"}, want: ResourceMetadata{Name: "config-name", Namespace: "config-namespace"}},
		{name: "valid templates", attrs: &authz.ResourceAttributes{Name: "{{.Name}}", Namespace: "{{.Namespace}}"}, want: ResourceMetadata{}},
		{name: "opening delimiter", attrs: &authz.ResourceAttributes{Name: "{{.Name", Namespace: "config-namespace"}, want: ResourceMetadata{Namespace: "config-namespace"}},
		{name: "closing delimiter", attrs: &authz.ResourceAttributes{Name: "config-name", Namespace: ".Namespace}}"}, want: ResourceMetadata{Name: "config-name"}},
		{name: "mixed static and template values", attrs: &authz.ResourceAttributes{Name: "config-name", Namespace: "{{.Namespace}}"}, want: ResourceMetadata{Name: "config-name"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StaticResourceMetadata(tt.attrs)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("metadata mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestResourceMetadataPrecedenceAndOptionalFields(t *testing.T) {
	logger := NewLogger(io.Discard, Options{
		Resource:              ResourceMetadata{Name: "explicit-name", Type: "CustomType"},
		AuthorizationResource: ResourceMetadata{Name: "static-name", Namespace: "static-namespace"},
		AIProvider:            "Provider",
		ProductVersion:        "test",
	})
	t.Cleanup(func() { closeLogger(t, logger) })
	request := httptest.NewRequest(http.MethodPost, "http://proxy/infer", nil)
	event := logger.event(request, &requestContext{resource: ResourceMetadata{Name: "request-name", Namespace: "request-namespace"}}, httpsnoop.Metrics{Code: http.StatusOK}, time.Unix(1, 0))
	want := []Resource{{Name: "explicit-name", Namespace: "request-namespace", Type: "CustomType", RoleID: resourceRoleTargetID, Role: resourceRoleTargetName}}
	if diff := cmp.Diff(want, event.Resources); diff != "" {
		t.Errorf("resource metadata mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(&AIModel{Name: "explicit-name", AIProvider: "Provider"}, event.AIModel); diff != "" {
		t.Errorf("AI model mismatch (-want +got):\n%s", diff)
	}

	logger = NewLogger(io.Discard, Options{
		Resource:              ResourceMetadata{Namespace: "explicit-namespace"},
		AuthorizationResource: ResourceMetadata{Name: "static-name", Namespace: "static-namespace"},
		ProductVersion:        "test",
	})
	t.Cleanup(func() { closeLogger(t, logger) })
	event = logger.event(request, &requestContext{}, httpsnoop.Metrics{Code: http.StatusOK}, time.Unix(1, 0))
	want = []Resource{{Name: "static-name", Namespace: "explicit-namespace", RoleID: resourceRoleTargetID, Role: resourceRoleTargetName}}
	if diff := cmp.Diff(want, event.Resources); diff != "" {
		t.Errorf("static resource fallback mismatch (-want +got):\n%s", diff)
	}
	if event.AIModel != nil {
		t.Errorf("empty provider must omit AI model: %+v", event.AIModel)
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), `"type":`) {
		t.Errorf("empty resource type must be omitted: %s", encoded)
	}

	logger = NewLogger(io.Discard, Options{
		Resource:       ResourceMetadata{Namespace: "explicit-namespace"},
		AIProvider:     "Provider",
		ProductVersion: "test",
	})
	t.Cleanup(func() { closeLogger(t, logger) })
	event = logger.event(request, &requestContext{}, httpsnoop.Metrics{Code: http.StatusOK}, time.Unix(1, 0))
	if len(event.Resources) != 0 || event.AIModel != nil {
		t.Errorf("unresolved resource name must omit resources and AI model: %+v", event)
	}
}
