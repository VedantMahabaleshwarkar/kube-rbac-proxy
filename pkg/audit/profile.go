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

import "fmt"

type Profile string

const (
	ProfileNone     Profile = "none"
	ProfileMetadata Profile = "metadata"
)

func (p Profile) Validate() error {
	switch p {
	case ProfileNone, ProfileMetadata:
		return nil
	default:
		return fmt.Errorf("audit log profile must be one of %q or %q, got %q", ProfileNone, ProfileMetadata, p)
	}
}

func (p Profile) String() string {
	return string(p)
}

func (p *Profile) Set(value string) error {
	candidate := Profile(value)
	if err := candidate.Validate(); err != nil {
		return err
	}
	*p = candidate
	return nil
}

func (p Profile) Type() string {
	return "string"
}
