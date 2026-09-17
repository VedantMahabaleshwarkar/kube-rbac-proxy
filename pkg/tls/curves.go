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

package tls

import (
	"fmt"
	"math"
	"strings"

	cryptotls "crypto/tls"
)

// ParseCurvePreferences validates numeric Go crypto/tls CurveID values without
// maintaining a version-specific list of curve names in this repository.
func ParseCurvePreferences(ids []int32) ([]cryptotls.CurveID, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	result := make([]cryptotls.CurveID, 0, len(ids))
	seen := make(map[cryptotls.CurveID]struct{}, len(ids))
	for _, id := range ids {
		if id < 1 || id > math.MaxUint16 {
			return nil, fmt.Errorf("TLS curve preference %d is out of range", id)
		}
		curve := cryptotls.CurveID(id)
		if strings.HasPrefix(curve.String(), "CurveID(") {
			return nil, fmt.Errorf("TLS curve preference %d is unsupported by this Go version", id)
		}
		if _, ok := seen[curve]; ok {
			return nil, fmt.Errorf("duplicate TLS curve preference %d", id)
		}
		seen[curve] = struct{}{}
		result = append(result, curve)
	}
	return result, nil
}
