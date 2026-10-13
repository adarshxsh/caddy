// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddyfile

import (
	"testing"
)

func TestFormattingDifferenceUnspacedQuotes(t *testing.T) {
	for i, tc := range []struct {
		description string
		input       string
	}{
		{
			description: "unspaced double quote with brace",
			input:       "key=\"foo { bar }\"\n",
		},
		{
			description: "unspaced double quote in directive argument",
			input:       "site.com {\n\theader_up Host\"{host}\"\n\tkey=\"foo { bar }\"\n}\n",
		},
	} {
		warning, different := FormattingDifference("Caddyfile", []byte(tc.input))
		if different {
			t.Errorf("[TEST %d: %s] Expected no formatting difference, but got warning: %s",
				i, tc.description, warning.Message)
		}
	}
}
