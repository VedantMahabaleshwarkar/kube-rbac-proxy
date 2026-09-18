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
	"net/http"
	"time"

	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

type requestTimeoutBudgetContextKey struct{}

type requestTimeoutBudget struct {
	authDeadline     time.Time
	upstreamDeadline time.Time
}

func newRequestTimeoutBudget(start time.Time, upstreamTimeout, authTimeout time.Duration) requestTimeoutBudget {
	budget := requestTimeoutBudget{}
	if upstreamTimeout > 0 {
		budget.upstreamDeadline = start.Add(upstreamTimeout)
	}
	if authTimeout > 0 {
		budget.authDeadline = start.Add(authTimeout)
	}
	if !budget.upstreamDeadline.IsZero() && (budget.authDeadline.IsZero() || budget.upstreamDeadline.Before(budget.authDeadline)) {
		budget.authDeadline = budget.upstreamDeadline
	}
	return budget
}

func withRequestTimeouts(next http.HandlerFunc, upstreamTimeout, authTimeout time.Duration) http.HandlerFunc {
	if upstreamTimeout <= 0 && authTimeout <= 0 {
		return next
	}

	return func(w http.ResponseWriter, req *http.Request) {
		if _, ok := req.Context().Value(requestTimeoutBudgetContextKey{}).(requestTimeoutBudget); ok {
			next.ServeHTTP(w, req)
			return
		}
		budget := newRequestTimeoutBudget(time.Now(), upstreamTimeout, authTimeout)
		ctx := context.WithValue(req.Context(), requestTimeoutBudgetContextKey{}, budget)
		next.ServeHTTP(w, req.WithContext(ctx))
	}
}

func withSharedAuthTimeout(next http.HandlerFunc, timeout time.Duration) http.HandlerFunc {
	return withRequestTimeouts(next, 0, timeout)
}

func contextWithAuthDeadline(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc, bool) {
	if budget, ok := ctx.Value(requestTimeoutBudgetContextKey{}).(requestTimeoutBudget); ok && !budget.authDeadline.IsZero() {
		deadlineCtx, cancel := context.WithDeadline(ctx, budget.authDeadline)
		return deadlineCtx, cancel, true
	}
	if timeout > 0 {
		timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
		return timeoutCtx, cancel, true
	}
	return ctx, nil, false
}

func withAuthenticationTimeout(next authenticator.Request, timeout time.Duration) authenticator.Request {
	return authenticator.RequestFunc(func(req *http.Request) (*authenticator.Response, bool, error) {
		ctx, cancel, enabled := contextWithAuthDeadline(req.Context(), timeout)
		if !enabled {
			return next.AuthenticateRequest(req)
		}
		defer cancel()
		response, authenticated, err := next.AuthenticateRequest(req.WithContext(ctx))
		if err == nil {
			if cause := context.Cause(ctx); cause != nil {
				return nil, false, cause
			}
		}
		return response, authenticated, err
	})
}

func withAuthorizationTimeout(next authorizer.Authorizer, timeout time.Duration) authorizer.Authorizer {
	return authorizer.AuthorizerFunc(func(ctx context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, error) {
		ctx, cancel, enabled := contextWithAuthDeadline(ctx, timeout)
		if !enabled {
			return next.Authorize(ctx, attrs)
		}
		defer cancel()
		decision, reason, err := next.Authorize(ctx, attrs)
		if err == nil {
			if cause := context.Cause(ctx); cause != nil {
				return authorizer.DecisionNoOpinion, "", cause
			}
		}
		return decision, reason, err
	})
}
