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
package app

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

func TestRequestTimeoutBudgetSharesOverallDeadline(t *testing.T) {
	start := time.Date(2026, time.September, 18, 10, 0, 0, 0, time.UTC)
	tests := []struct {
		name                 string
		upstreamTimeout      time.Duration
		authTimeout          time.Duration
		wantAuthDeadline     time.Time
		wantUpstreamDeadline time.Time
	}{
		{
			name:                 "overall timeout caps a longer auth timeout",
			upstreamTimeout:      500 * time.Millisecond,
			authTimeout:          30 * time.Second,
			wantAuthDeadline:     start.Add(500 * time.Millisecond),
			wantUpstreamDeadline: start.Add(500 * time.Millisecond),
		},
		{
			name:                 "shorter auth timeout fails before overall timeout",
			upstreamTimeout:      30 * time.Second,
			authTimeout:          500 * time.Millisecond,
			wantAuthDeadline:     start.Add(500 * time.Millisecond),
			wantUpstreamDeadline: start.Add(30 * time.Second),
		},
		{
			name:                 "disabled auth-specific timeout still consumes overall timeout",
			upstreamTimeout:      500 * time.Millisecond,
			wantAuthDeadline:     start.Add(500 * time.Millisecond),
			wantUpstreamDeadline: start.Add(500 * time.Millisecond),
		},
		{
			name:             "auth timeout remains active when overall timeout is disabled",
			authTimeout:      500 * time.Millisecond,
			wantAuthDeadline: start.Add(500 * time.Millisecond),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			budget := newRequestTimeoutBudget(start, tt.upstreamTimeout, tt.authTimeout)
			if !budget.authDeadline.Equal(tt.wantAuthDeadline) {
				t.Fatalf("auth deadline = %v, want %v", budget.authDeadline, tt.wantAuthDeadline)
			}
			if !budget.upstreamDeadline.Equal(tt.wantUpstreamDeadline) {
				t.Fatalf("upstream deadline = %v, want %v", budget.upstreamDeadline, tt.wantUpstreamDeadline)
			}
		})
	}
}

func TestAuthenticationTimeoutBoundsOnlyAuthenticatorCall(t *testing.T) {
	requestContext := make(chan context.Context, 1)
	next := authenticator.RequestFunc(func(req *http.Request) (*authenticator.Response, bool, error) {
		requestContext <- req.Context()
		<-req.Context().Done()
		return nil, false, context.Cause(req.Context())
	})

	req, err := http.NewRequest(http.MethodGet, "http://proxy.example", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	_, _, err = withAuthenticationTimeout(next, 10*time.Millisecond).AuthenticateRequest(req)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("AuthenticateRequest() error = %v, want context.DeadlineExceeded", err)
	}
	if _, ok := (<-requestContext).Deadline(); !ok {
		t.Fatal("authenticator context has no deadline")
	}
	if _, ok := req.Context().Deadline(); ok {
		t.Fatal("authentication deadline leaked into the original request context")
	}
	select {
	case <-req.Context().Done():
		t.Fatal("authentication timeout canceled the original request context")
	default:
	}
}

func TestAuthenticationTimeoutRejectsLateSuccess(t *testing.T) {
	next := authenticator.RequestFunc(func(req *http.Request) (*authenticator.Response, bool, error) {
		<-req.Context().Done()
		return &authenticator.Response{}, true, nil
	})

	req, err := http.NewRequest(http.MethodGet, "http://proxy.example", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	_, authenticated, err := withAuthenticationTimeout(next, 10*time.Millisecond).AuthenticateRequest(req)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("AuthenticateRequest() error = %v, want context.DeadlineExceeded", err)
	}
	if authenticated {
		t.Fatal("AuthenticateRequest() authenticated after its deadline expired")
	}
}

func TestAuthorizationTimeoutBoundsOnlyAuthorizerCall(t *testing.T) {
	authorizerContext := make(chan context.Context, 1)
	next := authorizer.AuthorizerFunc(func(ctx context.Context, _ authorizer.Attributes) (authorizer.Decision, string, error) {
		authorizerContext <- ctx
		<-ctx.Done()
		return authorizer.DecisionNoOpinion, "", context.Cause(ctx)
	})

	ctx := context.Background()
	_, _, err := withAuthorizationTimeout(next, 10*time.Millisecond).Authorize(ctx, authorizer.AttributesRecord{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Authorize() error = %v, want context.DeadlineExceeded", err)
	}
	if _, ok := (<-authorizerContext).Deadline(); !ok {
		t.Fatal("authorizer context has no deadline")
	}
	if _, ok := ctx.Deadline(); ok {
		t.Fatal("authorization deadline leaked into the original request context")
	}
	select {
	case <-ctx.Done():
		t.Fatal("authorization timeout canceled the original request context")
	default:
	}
}

func TestAuthorizationTimeoutRejectsLateAllow(t *testing.T) {
	next := authorizer.AuthorizerFunc(func(ctx context.Context, _ authorizer.Attributes) (authorizer.Decision, string, error) {
		<-ctx.Done()
		return authorizer.DecisionAllow, "late allow", nil
	})

	decision, _, err := withAuthorizationTimeout(next, 10*time.Millisecond).Authorize(context.Background(), authorizer.AttributesRecord{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Authorize() error = %v, want context.DeadlineExceeded", err)
	}
	if decision == authorizer.DecisionAllow {
		t.Fatal("Authorize() allowed after its deadline expired")
	}
}

func TestAuthTimeoutDisabledPreservesCallerContext(t *testing.T) {
	requestContext := make(chan context.Context, 1)
	authenticatorWithoutTimeout := authenticator.RequestFunc(func(req *http.Request) (*authenticator.Response, bool, error) {
		requestContext <- req.Context()
		return &authenticator.Response{}, true, nil
	})
	authorizerContext := make(chan context.Context, 1)
	authorizerWithoutTimeout := authorizer.AuthorizerFunc(func(ctx context.Context, _ authorizer.Attributes) (authorizer.Decision, string, error) {
		authorizerContext <- ctx
		return authorizer.DecisionAllow, "", nil
	})

	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://proxy.example", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if _, _, err := withAuthenticationTimeout(authenticatorWithoutTimeout, 0).AuthenticateRequest(req); err != nil {
		t.Fatalf("AuthenticateRequest() error: %v", err)
	}
	if _, _, err := withAuthorizationTimeout(authorizerWithoutTimeout, 0).Authorize(ctx, authorizer.AttributesRecord{}); err != nil {
		t.Fatalf("Authorize() error: %v", err)
	}

	if got := <-requestContext; got != ctx {
		t.Fatal("disabled authentication timeout replaced the caller context")
	}
	if got := <-authorizerContext; got != ctx {
		t.Fatal("disabled authorization timeout replaced the caller context")
	}
}
