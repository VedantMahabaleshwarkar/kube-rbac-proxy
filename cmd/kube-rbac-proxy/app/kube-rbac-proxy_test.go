/*
Copyright 2022 the kube-rbac-proxy maintainers. All rights reserved.

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
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/brancz/kube-rbac-proxy/pkg/audit"
	"github.com/brancz/kube-rbac-proxy/pkg/authn"
	"github.com/brancz/kube-rbac-proxy/pkg/authz"
	"github.com/brancz/kube-rbac-proxy/pkg/proxy"
	"github.com/google/go-cmp/cmp"

	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

func Test_parseAuthorizationConfigFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "configfile.yaml")

	tests := []struct {
		name        string
		fileContent string
		want        *authz.Config
		wantErr     bool
		wantErrSub  string
	}{
		{
			name: "resources",
			fileContent: `authorization:
  rewrites:
    byQueryParameter:
      name: "namespace"
  resourceAttributes:
    resource: namespaces
    subresource: metrics
    namespace: "{{ .Value }}"
  static:
    - user:
        name: system:serviceaccount:default:default
      resourceRequest: true
      resource: namespaces
      subresource: metrics
      namespace: default
      verb: get`,
			want: &authz.Config{
				Rewrites: &authz.SubjectAccessReviewRewrites{
					ByQueryParameter: &authz.QueryParameterRewriteConfig{
						Name: "namespace",
					},
				},
				ResourceAttributes: &authz.ResourceAttributes{
					Resource:    "namespaces",
					Subresource: "metrics",
					Namespace:   "{{ .Value }}",
				},
				Static: []authz.StaticAuthorizationConfig{
					{
						User: authz.UserConfig{
							Name: "system:serviceaccount:default:default",
						},
						ResourceRequest: true,
						Resource:        "namespaces",
						Subresource:     "metrics",
						Namespace:       "default",
						Verb:            "get",
					},
				},
			},
		},
		{
			name: "non-resources",
			fileContent: `authorization:
  static:
    - user:
        name: system:serviceaccount:default:default
      resourceRequest: false
      verb: get
      path: /metrics`,
			want: &authz.Config{
				Static: []authz.StaticAuthorizationConfig{
					{
						User: authz.UserConfig{
							Name: "system:serviceaccount:default:default",
						},
						ResourceRequest: false,
						Verb:            "get",
						Path:            "/metrics",
					},
				},
			},
		},
		{
			name: "Format1 and Format2 in same file",
			fileContent: `authorization:
  rewrites:
    byQueryParameter:
      name: "namespace"
  resourceAttributes:
    resource: namespaces
    subresource: metrics
    namespace: "{{ .Value }}"
  endpoints:
    - path: /api/v1/evaluations/jobs/*/events
      mappings:
        - methods: [post]
          resources:
            - rewrites:
                byHttpHeader:
                  name: X-Tenant
              resourceAttributes:
                namespace: "{{.FromHeader}}"
                apiGroup: trustyai.opendatahub.io
                resource: status-events
                verb: create`,
			want: &authz.Config{
				Rewrites: &authz.SubjectAccessReviewRewrites{
					ByQueryParameter: &authz.QueryParameterRewriteConfig{Name: "namespace"},
				},
				ResourceAttributes: &authz.ResourceAttributes{
					Resource:    "namespaces",
					Subresource: "metrics",
					Namespace:   "{{ .Value }}",
				},
				Endpoints: []authz.Endpoint{{
					Path: "/api/v1/evaluations/jobs/*/events",
					Mappings: []authz.EndpointMapping{{
						Methods: []string{"post"},
						Resources: []authz.EndpointResourceRule{{
							Rewrites: authz.SubjectAccessReviewRewrites{
								ByHTTPHeader: &authz.HTTPHeaderRewriteConfig{Name: "X-Tenant"},
							},
							ResourceAttributes: authz.ResourceAttributes{
								Namespace: "{{.FromHeader}}",
								APIGroup:  "trustyai.opendatahub.io",
								Resource:  "status-events",
								Verb:      "create",
							},
						}},
					}},
				}},
			},
		},
		{
			name: "Format2 mapping rejects empty methods list",
			fileContent: `authorization:
  endpoints:
    - path: /api/v1/x
      mappings:
        - methods: []
          resources:
            - resourceAttributes:
                resource: pods
                verb: get`,
			want:       nil,
			wantErr:    true,
			wantErrSub: "non-empty methods",
		},
		{
			name: "Format2 mapping rejects omitted methods",
			fileContent: `authorization:
  endpoints:
    - path: /api/v1/y
      mappings:
        - resources:
            - resourceAttributes:
                resource: pods
                verb: get`,
			want:       nil,
			wantErr:    true,
			wantErrSub: "non-empty methods",
		},
		{
			name: "Format2 mapping rejects empty resources list",
			fileContent: `authorization:
  endpoints:
    - path: /api/v1/z
      mappings:
        - methods: [get]
          resources: []`,
			want:       nil,
			wantErr:    true,
			wantErrSub: "resource rule",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.WriteFile(filePath, []byte(tt.fileContent), 0666); err != nil {
				t.Fatalf("failed to write file: %v", err)
			}

			got, err := parseAuthorizationConfigFile(filePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseAuthorizationConfigFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if tt.wantErrSub != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErrSub)) {
					t.Errorf("parseAuthorizationConfigFile() error = %v, want substring %q", err, tt.wantErrSub)
				}
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseAuthorizationConfigFile(): %s", cmp.Diff(got, tt.want))
			}
		})
	}
}

func TestBuildRequestHandlerAuditBoundaries(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		allowPaths   []string
		ignorePaths  []string
		wantStatus   int
		wantEvents   int
		wantDirect   bool
		auditEnabled bool
	}{
		{name: "protected request is audited", path: "/infer", wantStatus: http.StatusAccepted, wantEvents: 1, auditEnabled: true},
		{name: "auditing disabled produces no output", path: "/infer", wantStatus: http.StatusAccepted},
		{name: "ignored request bypasses audit", path: "/metrics", ignorePaths: []string{"/metrics"}, wantStatus: http.StatusNoContent, wantDirect: true, auditEnabled: true},
		{name: "allow path rejection happens before audit", path: "/blocked", allowPaths: []string{"/infer"}, wantStatus: http.StatusNotFound, auditEnabled: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			auditLogger := audit.NewLogger(&output, audit.Options{ProductVersion: "test"})
			protected := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusAccepted)
			})
			if tt.auditEnabled {
				protected = auditLogger.WithAuditLog(protected)
			}
			directCalled := false
			direct := func(w http.ResponseWriter, _ *http.Request) {
				directCalled = true
				w.WriteHeader(http.StatusNoContent)
			}
			handler := buildRequestHandler(direct, protected, tt.allowPaths, tt.ignorePaths, 0)

			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, tt.path, nil)
			req.RemoteAddr = "192.0.2.1:1234"
			handler(recorder, req)
			auditLogger.Close()

			if recorder.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", recorder.Code, tt.wantStatus)
			}
			if directCalled != tt.wantDirect {
				t.Errorf("direct handler called = %t, want %t", directCalled, tt.wantDirect)
			}

			decoder := json.NewDecoder(&output)
			events := 0
			for {
				var event audit.Event
				err := decoder.Decode(&event)
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("decode event: %v", err)
				}
				events++
			}
			if events != tt.wantEvents {
				t.Errorf("audit events = %d, want %d", events, tt.wantEvents)
			}
		})
	}
}

func TestBuildProtectedHandlerAuditsAccessFailures(t *testing.T) {
	tests := []struct {
		name          string
		authenticated bool
		decision      authorizer.Decision
		wantStatus    int
		wantUser      string
	}{
		{
			name:       "authentication failure",
			wantStatus: http.StatusUnauthorized,
			wantUser:   "Unknown",
		},
		{
			name:          "authorization failure",
			authenticated: true,
			decision:      authorizer.DecisionDeny,
			wantStatus:    http.StatusForbidden,
			wantUser:      "alice",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			auditLogger := audit.NewLogger(&output, audit.Options{ProductVersion: "test"})
			requestAuthenticator := authenticator.RequestFunc(func(*http.Request) (*authenticator.Response, bool, error) {
				if !tt.authenticated {
					return nil, false, nil
				}
				return &authenticator.Response{User: &user.DefaultInfo{Name: "alice"}}, true, nil
			})
			requestAuthorizer := authorizer.AuthorizerFunc(func(context.Context, authorizer.Attributes) (authorizer.Decision, string, error) {
				return tt.decision, "test decision", nil
			})
			authConfig := &proxy.Config{
				Authentication: &authn.AuthnConfig{
					Header: &authn.AuthnHeaderConfig{},
					Token:  &authn.TokenConfig{},
				},
				Authorization: &authz.Config{ResourceAttributes: &authz.ResourceAttributes{
					Resource: "inferenceservices",
					Verb:     "get",
				}},
			}
			upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusAccepted)
			})
			protected := buildProtectedHandler(upstream, authConfig, requestAuthenticator, requestAuthorizer, auditLogger)
			handler := buildRequestHandler(upstream, protected, nil, nil, 0)

			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/infer", nil)
			req.RemoteAddr = "192.0.2.1:1234"
			handler(recorder, req)
			auditLogger.Close()

			if recorder.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", recorder.Code, tt.wantStatus)
			}
			decoder := json.NewDecoder(&output)
			var event audit.Event
			if err := decoder.Decode(&event); err != nil {
				t.Fatalf("decode audit event: %v", err)
			}
			if event.HTTPResponse.Code != tt.wantStatus {
				t.Errorf("audit response code = %d, want %d", event.HTTPResponse.Code, tt.wantStatus)
			}
			if event.Status != "Failure" {
				t.Errorf("audit status = %q, want Failure", event.Status)
			}
			if event.Actor.User.Name != tt.wantUser {
				t.Errorf("audit user = %q, want %q", event.Actor.User.Name, tt.wantUser)
			}
			if err := decoder.Decode(&audit.Event{}); err != io.EOF {
				t.Fatalf("expected exactly one audit event, got trailing decode error %v", err)
			}
		})
	}
}
