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
	"net/http/httputil"
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
			o.AuditLogProfile = audit.ProfileMetadata
			o.AuditResourceName = "explicit-model"
			o.AuditResourceNamespace = "explicit-namespace"
			o.AuditResourceType = "InferenceService"
			o.AuditAIProvider = "KServe"
			o.AuditUseForwardedFor = true
			o.AuthTimeout = 17 * time.Second
			tt.authorizationResource.Resource = "inferenceservices"
			o.Auth.Authorization.ResourceAttributes = &tt.authorizationResource

			completed, err := Complete(o)
			if err != nil {
				t.Fatalf("Complete() error: %v", err)
			}
			if completed.auditLogProfile != audit.ProfileMetadata {
				t.Fatalf("auditLogProfile = %q, want %q", completed.auditLogProfile, audit.ProfileMetadata)
			}
			if completed.kubeClient == nil {
				t.Fatal("kubeClient = nil, want client constructed without a live request")
			}
			if completed.authTimeout != 17*time.Second {
				t.Fatalf("authTimeout = %v, want 17s", completed.authTimeout)
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

func TestCommandExposesAuthTimeout(t *testing.T) {
	cmd := NewKubeRBACProxyCommand()
	flag := cmd.Flags().Lookup("auth-timeout")
	if flag == nil {
		t.Fatal("flag --auth-timeout is not registered on the command")
	}
	if flag.DefValue != "30s" {
		t.Fatalf("--auth-timeout default = %q, want 30s", flag.DefValue)
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
		"audit-log-profile",
		"audit-resource-name",
		"audit-resource-namespace",
		"audit-resource-type",
		"audit-use-forwarded-for",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("audit flags mismatch (-want +got):\n%s", diff)
	}
	for _, oldName := range []string{"audit-log-enabled", "audit-isvc-name", "audit-isvc-namespace"} {
		if cmd.Flags().Lookup(oldName) != nil {
			t.Errorf("obsolete flag %q is still registered", oldName)
		}
	}
}

func TestNewAuditLoggerSelectsImplementedProfile(t *testing.T) {
	tests := []struct {
		name       string
		profile    audit.Profile
		wantLogger bool
		wantErr    bool
	}{
		{name: "none", profile: audit.ProfileNone},
		{name: "metadata", profile: audit.ProfileMetadata, wantLogger: true},
		{name: "unimplemented", profile: audit.Profile("request"), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, err := newAuditLogger(tt.profile, io.Discard, audit.Options{})
			if (err != nil) != tt.wantErr {
				t.Fatalf("newAuditLogger() error = %v, wantErr %t", err, tt.wantErr)
			}
			if (logger != nil) != tt.wantLogger {
				t.Fatalf("newAuditLogger() logger present = %t, want %t", logger != nil, tt.wantLogger)
			}
			if logger != nil {
				closeAuditLogger(t, logger)
			}
		})
	}
}

func TestConfigureAuditResponseCapture(t *testing.T) {
	var output bytes.Buffer
	logger := audit.NewLogger(&output, audit.Options{ProductVersion: "test"})
	previousCalled := false
	reverseProxy := &httputil.ReverseProxy{
		ModifyResponse: func(*http.Response) error {
			previousCalled = true
			return nil
		},
	}
	configureAuditResponseCapture(reverseProxy, logger)
	handler := logger.WithAuditLog(func(_ http.ResponseWriter, req *http.Request) {
		if err := reverseProxy.ModifyResponse(&http.Response{
			StatusCode: http.StatusSwitchingProtocols,
			Request:    req,
		}); err != nil {
			t.Fatalf("ModifyResponse() error: %v", err)
		}
	})

	handler(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/upgrade", nil))
	closeAuditLogger(t, logger)

	if !previousCalled {
		t.Fatal("existing ModifyResponse hook was not called")
	}
	events := decodeAuditEvents(t, &output)
	if len(events) != 1 || events[0].HTTPResponse.Code != http.StatusSwitchingProtocols {
		t.Fatalf("captured events = %+v, want one event with status 101", events)
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
		auditProfile  audit.Profile
		wantStatus    int
		wantEvents    int
		wantDirect    bool
		wantProtected bool
	}{
		{
			name:          "protected request is audited",
			path:          "/infer",
			auditProfile:  audit.ProfileMetadata,
			wantStatus:    http.StatusAccepted,
			wantEvents:    1,
			wantProtected: true,
		},
		{
			name:          "auditing disabled produces no output",
			path:          "/infer",
			auditProfile:  audit.ProfileNone,
			wantStatus:    http.StatusAccepted,
			wantProtected: true,
		},
		{
			name:         "ignored request bypasses audit",
			path:         "/metrics",
			ignorePaths:  []string{"/metrics"},
			auditProfile: audit.ProfileMetadata,
			wantStatus:   http.StatusNoContent,
			wantDirect:   true,
		},
		{
			name:         "allow path rejection happens before audit",
			path:         "/blocked",
			allowPaths:   []string{"/infer"},
			auditProfile: audit.ProfileMetadata,
			wantStatus:   http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			auditLogger, err := newAuditLogger(tt.auditProfile, &output, audit.Options{
				Resource: audit.ResourceMetadata{
					Name:      "route-model",
					Namespace: "route-namespace",
					Type:      "InferenceService",
				},
				ProductVersion: "test",
			})
			if err != nil {
				t.Fatalf("newAuditLogger() error: %v", err)
			}
			protectedCalled := false
			protected := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				protectedCalled = true
				w.WriteHeader(http.StatusAccepted)
			})
			if auditLogger != nil {
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
			if auditLogger != nil {
				closeAuditLogger(t, auditLogger)
			}

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
		auditProfile   audit.Profile
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
			auditProfile:   audit.ProfileMetadata,
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
			auditProfile:   audit.ProfileMetadata,
			wantStatus:     http.StatusUnauthorized,
			wantEvents:     1,
			wantAuditUser:  audit.User{Name: "Unknown", TypeID: 0},
			wantStatusName: "Failure",
			wantStatusID:   2,
		},
		{
			name:           "authorization denial retains observed resource",
			auditProfile:   audit.ProfileMetadata,
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
			auditProfile:  audit.ProfileNone,
			authenticated: true,
			decision:      authorizer.DecisionAllow,
			wantStatus:    http.StatusOK,
			wantUpstream:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			// Deliberately omit explicit and static fallback metadata. In the
			// denial case, any emitted resource must have been observed before
			// the authorizer rejected the request.
			auditLogger, err := newAuditLogger(tt.auditProfile, &output, audit.Options{ProductVersion: "test"})
			if err != nil {
				t.Fatalf("newAuditLogger() error: %v", err)
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
			protected := buildProtectedHandler(upstream, authConfig, requestAuthenticator, requestAuthorizer, 0, auditLogger)
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

func TestBuildProtectedHandlerEnforcesAuthTimeoutWithoutConstrainingUpstream(t *testing.T) {
	const timeout = 10 * time.Millisecond
	authConfig := &proxy.Config{
		Authentication: &authn.AuthnConfig{
			Header: &authn.AuthnHeaderConfig{},
			Token:  &authn.TokenConfig{},
		},
		Authorization: &authz.Config{ResourceAttributes: &authz.ResourceAttributes{
			Resource: "inferenceservices",
			Verb:     "create",
			Name:     "model",
		}},
	}
	authenticated := authenticator.RequestFunc(func(*http.Request) (*authenticator.Response, bool, error) {
		return &authenticator.Response{User: &user.DefaultInfo{Name: "alice"}}, true, nil
	})
	allowed := authorizer.AuthorizerFunc(func(context.Context, authorizer.Attributes) (authorizer.Decision, string, error) {
		return authorizer.DecisionAllow, "", nil
	})

	t.Run("authentication and authorization share one deadline", func(t *testing.T) {
		var authenticationDeadline time.Time
		sharedDeadlineAuthenticator := authenticator.RequestFunc(func(req *http.Request) (*authenticator.Response, bool, error) {
			var ok bool
			authenticationDeadline, ok = req.Context().Deadline()
			if !ok {
				t.Fatal("authentication context has no deadline")
			}
			time.Sleep(timeout)
			return &authenticator.Response{User: &user.DefaultInfo{Name: "alice"}}, true, nil
		})
		var authorizationDeadline time.Time
		sharedDeadlineAuthorizer := authorizer.AuthorizerFunc(func(ctx context.Context, _ authorizer.Attributes) (authorizer.Decision, string, error) {
			var ok bool
			authorizationDeadline, ok = ctx.Deadline()
			if !ok {
				t.Fatal("authorization context has no deadline")
			}
			return authorizer.DecisionAllow, "", nil
		})
		upstream := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if _, ok := req.Context().Deadline(); ok {
				t.Error("auth deadline leaked into upstream request context")
			}
			w.WriteHeader(http.StatusNoContent)
		})
		handler := buildProtectedHandler(upstream, authConfig, sharedDeadlineAuthenticator, sharedDeadlineAuthorizer, time.Second, nil)

		recorder := httptest.NewRecorder()
		handler(recorder, httptest.NewRequest(http.MethodPost, "/infer", nil))
		if recorder.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNoContent)
		}
		if !authenticationDeadline.Equal(authorizationDeadline) {
			t.Fatalf("authentication deadline = %v, authorization deadline = %v; want one shared deadline", authenticationDeadline, authorizationDeadline)
		}
	})

	t.Run("authentication timeout remains unauthorized", func(t *testing.T) {
		timedOutAuthenticator := authenticator.RequestFunc(func(req *http.Request) (*authenticator.Response, bool, error) {
			<-req.Context().Done()
			return nil, false, context.Cause(req.Context())
		})
		upstream := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("upstream called after authentication timeout")
		})
		handler := buildProtectedHandler(upstream, authConfig, timedOutAuthenticator, allowed, timeout, nil)

		recorder := httptest.NewRecorder()
		handler(recorder, httptest.NewRequest(http.MethodPost, "/infer", nil))
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
		}
	})

	t.Run("authorization timeout remains an internal error", func(t *testing.T) {
		timedOutAuthorizer := authorizer.AuthorizerFunc(func(ctx context.Context, _ authorizer.Attributes) (authorizer.Decision, string, error) {
			<-ctx.Done()
			return authorizer.DecisionNoOpinion, "", context.Cause(ctx)
		})
		upstream := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("upstream called after authorization timeout")
		})
		handler := buildProtectedHandler(upstream, authConfig, authenticated, timedOutAuthorizer, timeout, nil)

		recorder := httptest.NewRecorder()
		handler(recorder, httptest.NewRequest(http.MethodPost, "/infer", nil))
		if recorder.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want %d", recorder.Code, http.StatusInternalServerError)
		}
	})

	t.Run("upstream request keeps its original lifetime", func(t *testing.T) {
		upstream := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if _, ok := req.Context().Deadline(); ok {
				t.Error("auth timeout leaked into upstream request context")
			}
			time.Sleep(3 * timeout)
			w.WriteHeader(http.StatusNoContent)
		})
		handler := buildProtectedHandler(upstream, authConfig, authenticated, allowed, timeout, nil)

		recorder := httptest.NewRecorder()
		handler(recorder, httptest.NewRequest(http.MethodPost, "/infer", nil))
		if recorder.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNoContent)
		}
	})
}

func TestOverallTimeoutCapsAuthenticationBeforeUpstream(t *testing.T) {
	const (
		upstreamTimeout = 10 * time.Millisecond
		authTimeout     = time.Second
	)
	authConfig := &proxy.Config{
		Authentication: &authn.AuthnConfig{
			Header: &authn.AuthnHeaderConfig{},
			Token:  &authn.TokenConfig{},
		},
		Authorization: &authz.Config{ResourceAttributes: &authz.ResourceAttributes{
			Resource: "inferenceservices",
			Verb:     "create",
		}},
	}
	var authenticationDeadline time.Time
	timedOutAuthenticator := authenticator.RequestFunc(func(req *http.Request) (*authenticator.Response, bool, error) {
		var ok bool
		authenticationDeadline, ok = req.Context().Deadline()
		if !ok {
			t.Fatal("authentication context has no overall deadline")
		}
		<-req.Context().Done()
		return nil, false, context.Cause(req.Context())
	})
	requestAuthorizer := authorizer.AuthorizerFunc(func(context.Context, authorizer.Attributes) (authorizer.Decision, string, error) {
		t.Fatal("authorization called after the overall deadline expired during authentication")
		return authorizer.DecisionNoOpinion, "", nil
	})
	upstream := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("upstream called after the overall deadline expired during authentication")
	})
	protected := buildProtectedHandler(upstream, authConfig, timedOutAuthenticator, requestAuthorizer, authTimeout, nil)
	handler := withRequestTimeouts(buildRequestHandler(upstream, protected, nil, nil), upstreamTimeout, authTimeout)

	started := time.Now()
	recorder := httptest.NewRecorder()
	handler(recorder, httptest.NewRequest(http.MethodPost, "/infer", nil))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
	if latestExpectedDeadline := started.Add(10 * upstreamTimeout); authenticationDeadline.After(latestExpectedDeadline) {
		t.Fatalf("authentication deadline = %v, want overall deadline near %v rather than a reset auth deadline", authenticationDeadline, started.Add(upstreamTimeout))
	}
}

func TestBuildProtectedHandlerAuditsFormat2Ownership(t *testing.T) {
	authConfig := &proxy.Config{
		Authentication: &authn.AuthnConfig{
			Header: &authn.AuthnHeaderConfig{},
			Token:  &authn.TokenConfig{},
		},
		Authorization: &authz.Config{
			ResourceAttributes: &authz.ResourceAttributes{
				Resource:  "inferenceservices",
				Verb:      "get",
				Name:      "format1-model",
				Namespace: "format1-namespace",
			},
			Endpoints: []authz.Endpoint{{
				Path: "/v1/models/{model}/predict",
				Mappings: []authz.EndpointMapping{{
					Methods: []string{http.MethodPost},
					Resources: []authz.EndpointResourceRule{{
						Rewrites: authz.SubjectAccessReviewRewrites{
							ByHTTPHeader: &authz.HTTPHeaderRewriteConfig{Name: "X-Model-Name"},
						},
						ResourceAttributes: authz.ResourceAttributes{
							Resource:  "inferenceservices",
							Name:      "{{ .FromHeader }}",
							Namespace: "models",
						},
					}},
				}},
			}},
		},
	}
	authConfig.Authorization.PrepareEndpoints()

	tests := []struct {
		name         string
		method       string
		path         string
		modelHeader  string
		wantStatus   int
		wantResource []audit.Resource
	}{
		{
			name:       "matched endpoint with missing header",
			method:     http.MethodPost,
			path:       "/v1/models/fraud-detector/predict",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "matched endpoint with disallowed method",
			method:     http.MethodGet,
			path:       "/v1/models/fraud-detector/predict",
			wantStatus: http.StatusForbidden,
		},
		{
			name:        "matched endpoint with resolved attributes",
			method:      http.MethodPost,
			path:        "/v1/models/fraud-detector/predict",
			modelHeader: "request-model",
			wantStatus:  http.StatusNoContent,
			wantResource: []audit.Resource{{
				Name:      "request-model",
				Namespace: "models",
				Type:      "InferenceService",
				RoleID:    1,
				Role:      "Target",
			}},
		},
		{
			name:       "nonmatching endpoint uses Format1",
			method:     http.MethodGet,
			path:       "/healthz",
			wantStatus: http.StatusNoContent,
			wantResource: []audit.Resource{{
				Name:      "format1-model",
				Namespace: "format1-namespace",
				Type:      "InferenceService",
				RoleID:    1,
				Role:      "Target",
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			logger := audit.NewLogger(&output, audit.Options{
				Resource:              audit.ResourceMetadata{Type: "InferenceService"},
				AuthorizationResource: audit.ResourceMetadata{Name: "format1-model", Namespace: "format1-namespace"},
				ProductVersion:        "test",
			})
			requestAuthenticator := authenticator.RequestFunc(func(*http.Request) (*authenticator.Response, bool, error) {
				return &authenticator.Response{User: &user.DefaultInfo{Name: "alice"}}, true, nil
			})
			requestAuthorizer := authorizer.AuthorizerFunc(func(context.Context, authorizer.Attributes) (authorizer.Decision, string, error) {
				return authorizer.DecisionAllow, "", nil
			})
			upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			})
			handler := buildProtectedHandler(upstream, authConfig, requestAuthenticator, requestAuthorizer, 0, logger)

			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(tt.method, tt.path, nil)
			if tt.modelHeader != "" {
				req.Header.Set("X-Model-Name", tt.modelHeader)
			}
			handler(recorder, req)
			closeAuditLogger(t, logger)

			if recorder.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", recorder.Code, tt.wantStatus)
			}
			events := decodeAuditEvents(t, &output)
			if len(events) != 1 {
				t.Fatalf("audit events = %d, want 1", len(events))
			}
			if diff := cmp.Diff(tt.wantResource, events[0].Resources); diff != "" {
				t.Errorf("resources mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
