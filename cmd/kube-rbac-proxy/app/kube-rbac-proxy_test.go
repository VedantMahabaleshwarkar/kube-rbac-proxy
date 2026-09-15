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
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/brancz/kube-rbac-proxy/cmd/kube-rbac-proxy/app/options"
	"github.com/brancz/kube-rbac-proxy/pkg/audit"
	"github.com/brancz/kube-rbac-proxy/pkg/authn"
	"github.com/brancz/kube-rbac-proxy/pkg/authz"
	"github.com/brancz/kube-rbac-proxy/pkg/proxy"
	"github.com/google/go-cmp/cmp"
	"github.com/spf13/pflag"

	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/component-base/version"
)

func closeAuditLogger(t *testing.T, logger *audit.Logger) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := logger.Close(ctx); err != nil {
		t.Fatalf("close audit logger: %v", err)
	}
}

func decodeAuditEvents(t *testing.T, output *bytes.Buffer) []audit.Event {
	t.Helper()

	decoder := json.NewDecoder(output)
	var events []audit.Event
	for {
		var event audit.Event
		err := decoder.Decode(&event)
		if err == io.EOF {
			return events
		}
		if err != nil {
			t.Fatalf("decode audit event: %v", err)
		}
		events = append(events, event)
	}
}

func TestCompleteBuildsAuditOptions(t *testing.T) {
	wantUpstream, err := url.Parse("https://upstream.example.test:8443/v1")
	if err != nil {
		t.Fatalf("parse expected upstream: %v", err)
	}
	tests := []struct {
		name                      string
		authorizationResource     authz.ResourceAttributes
		wantAuthorizationResource audit.ResourceMetadata
	}{
		{
			name: "static name and namespace are retained",
			authorizationResource: authz.ResourceAttributes{
				Name:      "static-model",
				Namespace: "static-namespace",
			},
			wantAuthorizationResource: audit.ResourceMetadata{
				Name:      "static-model",
				Namespace: "static-namespace",
			},
		},
		{
			name: "template namespace is omitted independently",
			authorizationResource: authz.ResourceAttributes{
				Name:      "static-model",
				Namespace: "{{ .Value }}",
			},
			wantAuthorizationResource: audit.ResourceMetadata{Name: "static-model"},
		},
		{
			name: "template name and namespace are omitted",
			authorizationResource: authz.ResourceAttributes{
				Name:      "{{ .Value }}",
				Namespace: "namespace-{{ .Value }}",
			},
		},
		{
			name: "one-sided template delimiters are omitted",
			authorizationResource: authz.ResourceAttributes{
				Name:      "model-{{",
				Namespace: "namespace-}}",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kubeconfigPath := filepath.Join(t.TempDir(), "kubeconfig")
			kubeconfig := clientcmdapi.Config{
				Clusters: map[string]*clientcmdapi.Cluster{
					"test": {
						Server:                "https://127.0.0.1",
						InsecureSkipTLSVerify: true,
					},
				},
				AuthInfos: map[string]*clientcmdapi.AuthInfo{
					"test": {Token: "test-token"},
				},
				Contexts: map[string]*clientcmdapi.Context{
					"test": {Cluster: "test", AuthInfo: "test"},
				},
				CurrentContext: "test",
			}
			if err := clientcmd.WriteToFile(kubeconfig, kubeconfigPath); err != nil {
				t.Fatalf("write kubeconfig: %v", err)
			}

			o := options.NewProxyRunOptions()
			o.KubeconfigLocation = kubeconfigPath
			o.Upstream = "https://upstream.example.test:8443/v1"
			o.AuditLogEnabled = true
			o.AuditResourceName = "explicit-model"
			o.AuditResourceNamespace = "explicit-namespace"
			o.AuditResourceType = "InferenceService"
			o.AuditAIProvider = "KServe"
			o.AuditUseForwardedFor = true
			tt.authorizationResource.Resource = "inferenceservices"
			o.Auth.Authorization.ResourceAttributes = &tt.authorizationResource

			completed, err := Complete(o)
			if err != nil {
				t.Fatalf("Complete() error: %v", err)
			}
			if !completed.auditLogEnabled {
				t.Fatal("auditLogEnabled = false, want true")
			}
			if completed.kubeClient == nil {
				t.Fatal("kubeClient = nil, want client constructed without a live request")
			}

			want := audit.Options{
				Resource: audit.ResourceMetadata{
					Name:      "explicit-model",
					Namespace: "explicit-namespace",
					Type:      "InferenceService",
				},
				AuthorizationResource: tt.wantAuthorizationResource,
				AIProvider:            "KServe",
				UseForwardedFor:       true,
				UpstreamURL:           wantUpstream,
				ProductVersion:        version.Get().GitVersion,
			}
			if diff := cmp.Diff(want, completed.auditOptions); diff != "" {
				t.Errorf("audit options mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCommandExposesAuditFlags(t *testing.T) {
	cmd := NewKubeRBACProxyCommand()
	var got []string
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if strings.HasPrefix(flag.Name, "audit-") {
			got = append(got, flag.Name)
		}
	})
	sort.Strings(got)
	want := []string{
		"audit-ai-provider",
		"audit-log-enabled",
		"audit-resource-name",
		"audit-resource-namespace",
		"audit-resource-type",
		"audit-use-forwarded-for",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("audit flags mismatch (-want +got):\n%s", diff)
	}
	for _, oldName := range []string{"audit-isvc-name", "audit-isvc-namespace"} {
		if cmd.Flags().Lookup(oldName) != nil {
			t.Errorf("obsolete flag %q is still registered", oldName)
		}
	}
}

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
		name          string
		path          string
		allowPaths    []string
		ignorePaths   []string
		auditEnabled  bool
		wantStatus    int
		wantEvents    int
		wantDirect    bool
		wantProtected bool
	}{
		{
			name:          "protected request is audited",
			path:          "/infer",
			auditEnabled:  true,
			wantStatus:    http.StatusAccepted,
			wantEvents:    1,
			wantProtected: true,
		},
		{
			name:          "auditing disabled produces no output",
			path:          "/infer",
			wantStatus:    http.StatusAccepted,
			wantProtected: true,
		},
		{
			name:         "ignored request bypasses audit",
			path:         "/metrics",
			ignorePaths:  []string{"/metrics"},
			auditEnabled: true,
			wantStatus:   http.StatusNoContent,
			wantDirect:   true,
		},
		{
			name:         "allow path rejection happens before audit",
			path:         "/blocked",
			allowPaths:   []string{"/infer"},
			auditEnabled: true,
			wantStatus:   http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			auditLogger := audit.NewLogger(&output, audit.Options{
				Resource: audit.ResourceMetadata{
					Name:      "route-model",
					Namespace: "route-namespace",
					Type:      "InferenceService",
				},
				ProductVersion: "test",
			})
			protectedCalled := false
			protected := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				protectedCalled = true
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
			handler := buildRequestHandler(direct, protected, tt.allowPaths, tt.ignorePaths)

			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, tt.path, nil)
			req.RemoteAddr = "192.0.2.1:1234"
			handler(recorder, req)
			closeAuditLogger(t, auditLogger)

			if recorder.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", recorder.Code, tt.wantStatus)
			}
			if directCalled != tt.wantDirect {
				t.Errorf("direct handler called = %t, want %t", directCalled, tt.wantDirect)
			}
			if protectedCalled != tt.wantProtected {
				t.Errorf("protected handler called = %t, want %t", protectedCalled, tt.wantProtected)
			}

			events := decodeAuditEvents(t, &output)
			if len(events) != tt.wantEvents {
				t.Fatalf("audit events = %d, want %d", len(events), tt.wantEvents)
			}
			if tt.wantEvents == 1 {
				event := events[0]
				if event.HTTPResponse.Code != http.StatusAccepted || event.StatusCode != "202" {
					t.Errorf("audit response = (%d, %q), want (202, %q)", event.HTTPResponse.Code, event.StatusCode, "202")
				}
				if event.Status != "Success" || event.StatusID != 1 {
					t.Errorf("audit status = (%q, %d), want (Success, 1)", event.Status, event.StatusID)
				}
				wantUser := audit.User{Name: "Unknown", TypeID: 0}
				if diff := cmp.Diff(wantUser, event.Actor.User); diff != "" {
					t.Errorf("audit user mismatch (-want +got):\n%s", diff)
				}
				if event.API.Operation != "POST /infer" || event.HTTPRequest.URL.Path != "/infer" {
					t.Errorf("audit operation/path = (%q, %q), want (%q, %q)", event.API.Operation, event.HTTPRequest.URL.Path, "POST /infer", "/infer")
				}
				wantResources := []audit.Resource{{
					Name:      "route-model",
					Namespace: "route-namespace",
					Type:      "InferenceService",
					RoleID:    1,
					Role:      "Target",
				}}
				if diff := cmp.Diff(wantResources, event.Resources); diff != "" {
					t.Errorf("audit resources mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestBuildProtectedHandlerAuditsFullChain(t *testing.T) {
	tests := []struct {
		name           string
		auditEnabled   bool
		authenticated  bool
		decision       authorizer.Decision
		wantStatus     int
		wantEvents     int
		wantUpstream   bool
		wantAuditUser  audit.User
		wantStatusName string
		wantStatusID   int
		wantResource   bool
	}{
		{
			name:           "authorized request reaches upstream",
			auditEnabled:   true,
			authenticated:  true,
			decision:       authorizer.DecisionAllow,
			wantStatus:     http.StatusOK,
			wantEvents:     1,
			wantUpstream:   true,
			wantAuditUser:  audit.User{Name: "alice", UID: "alice-uid", TypeID: 1, Groups: []audit.Group{{Name: "developers"}}},
			wantStatusName: "Success",
			wantStatusID:   1,
			wantResource:   true,
		},
		{
			name:           "authentication failure",
			auditEnabled:   true,
			wantStatus:     http.StatusUnauthorized,
			wantEvents:     1,
			wantAuditUser:  audit.User{Name: "Unknown", TypeID: 0},
			wantStatusName: "Failure",
			wantStatusID:   2,
		},
		{
			name:           "authorization denial retains observed resource",
			auditEnabled:   true,
			authenticated:  true,
			decision:       authorizer.DecisionDeny,
			wantStatus:     http.StatusForbidden,
			wantEvents:     1,
			wantAuditUser:  audit.User{Name: "alice", UID: "alice-uid", TypeID: 1, Groups: []audit.Group{{Name: "developers"}}},
			wantStatusName: "Failure",
			wantStatusID:   2,
			wantResource:   true,
		},
		{
			name:          "auditing disabled",
			authenticated: true,
			decision:      authorizer.DecisionAllow,
			wantStatus:    http.StatusOK,
			wantUpstream:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			var auditLogger *audit.Logger
			if tt.auditEnabled {
				// Deliberately omit explicit and static fallback metadata. In the
				// denial case, any emitted resource must have been observed before
				// the authorizer rejected the request.
				auditLogger = audit.NewLogger(&output, audit.Options{ProductVersion: "test"})
			}
			requestAuthenticator := authenticator.RequestFunc(func(*http.Request) (*authenticator.Response, bool, error) {
				if !tt.authenticated {
					return nil, false, nil
				}
				return &authenticator.Response{User: &user.DefaultInfo{
					Name:   "alice",
					UID:    "alice-uid",
					Groups: []string{"developers"},
				}}, true, nil
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
					Resource:  "inferenceservices",
					Verb:      "create",
					Name:      "observed-model",
					Namespace: "observed-namespace",
				}},
			}
			upstreamCalled := false
			upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				upstreamCalled = true
				w.WriteHeader(http.StatusOK)
			})
			protected := buildProtectedHandler(upstream, authConfig, requestAuthenticator, requestAuthorizer, auditLogger)
			handler := buildRequestHandler(upstream, protected, nil, nil)

			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/infer", nil)
			req.RemoteAddr = "192.0.2.1:1234"
			handler(recorder, req)
			if auditLogger != nil {
				closeAuditLogger(t, auditLogger)
			}

			if recorder.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", recorder.Code, tt.wantStatus)
			}
			if upstreamCalled != tt.wantUpstream {
				t.Errorf("upstream called = %t, want %t", upstreamCalled, tt.wantUpstream)
			}

			events := decodeAuditEvents(t, &output)
			if len(events) != tt.wantEvents {
				t.Fatalf("audit events = %d, want %d", len(events), tt.wantEvents)
			}
			if tt.wantEvents == 0 {
				return
			}

			event := events[0]
			if event.HTTPResponse.Code != tt.wantStatus || event.StatusCode != strconv.Itoa(tt.wantStatus) {
				t.Errorf("audit response = (%d, %q), want (%d, %q)", event.HTTPResponse.Code, event.StatusCode, tt.wantStatus, strconv.Itoa(tt.wantStatus))
			}
			if event.Status != tt.wantStatusName || event.StatusID != tt.wantStatusID {
				t.Errorf("audit status = (%q, %d), want (%q, %d)", event.Status, event.StatusID, tt.wantStatusName, tt.wantStatusID)
			}
			if diff := cmp.Diff(tt.wantAuditUser, event.Actor.User); diff != "" {
				t.Errorf("audit user mismatch (-want +got):\n%s", diff)
			}
			if event.API.Operation != "POST /infer" || event.HTTPRequest.URL.Path != "/infer" {
				t.Errorf("audit operation/path = (%q, %q), want (%q, %q)", event.API.Operation, event.HTTPRequest.URL.Path, "POST /infer", "/infer")
			}
			wantResources := []audit.Resource(nil)
			if tt.wantResource {
				wantResources = []audit.Resource{{
					Name:      "observed-model",
					Namespace: "observed-namespace",
					RoleID:    1,
					Role:      "Target",
				}}
			}
			if diff := cmp.Diff(wantResources, event.Resources); diff != "" {
				t.Errorf("audit resources mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
