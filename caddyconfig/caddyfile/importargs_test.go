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

func TestParseVariadicClamping(t *testing.T) {
	for i, tc := range []struct {
		input          string
		argCount       int
		expectedFound  bool
		expectedStart  int
		expectedEnd    int
	}{
		{
			input:          "{args[0:5]}",
			argCount:       2,
			expectedFound:  true,
			expectedStart:  0,
			expectedEnd:    2,
		},
		{
			input:          "{args[1:5]}",
			argCount:       2,
			expectedFound:  true,
			expectedStart:  1,
			expectedEnd:    2,
		},
		{
			input:          "{args[2:5]}",
			argCount:       2,
			expectedFound:  true,
			expectedStart:  2,
			expectedEnd:    2,
		},
		{
			input:          "{args[3:5]}",
			argCount:       2,
			expectedFound:  true,
			expectedStart:  2,
			expectedEnd:    2,
		},
		{
			input:          "{args[0:]}",
			argCount:       2,
			expectedFound:  true,
			expectedStart:  0,
			expectedEnd:    2,
		},
		{
			input:          "{args[2:]}",
			argCount:       2,
			expectedFound:  true,
			expectedStart:  2,
			expectedEnd:    2,
		},
		{
			input:          "{args[-1:]}",
			argCount:       2,
			expectedFound:  false,
			expectedStart:  0,
			expectedEnd:    0,
		},
		{
			input:          "{args[5:2]}",
			argCount:       2,
			expectedFound:  false,
			expectedStart:  0,
			expectedEnd:    0,
		},
	} {
		token := Token{
			File: "test",
			Line: 1,
			Text: tc.input,
		}
		found, start, end := parseVariadic(token, tc.argCount)
		if found != tc.expectedFound || start != tc.expectedStart || end != tc.expectedEnd {
			t.Errorf("Test %d (%s with %d args): expected (%t, %d, %d), got (%t, %d, %d)",
				i, tc.input, tc.argCount, tc.expectedFound, tc.expectedStart, tc.expectedEnd, found, start, end)
		}
	}
}

func TestVariadicImportExpansionClamping(t *testing.T) {
	// Test expanding {args[0:5]} when only 2 args are provided
	p := testParser(`
		(snippet) {
			echo {args[0:5]}
		}
		http://example.com {
			import snippet arg1 arg2
		}
	`)
	blocks, err := p.parseAll()
	if err != nil {
		t.Fatalf("Unexpected error during parsing: %v", err)
	}
	if len(blocks) != 1 {
		t.Fatalf("Expected 1 block, got %d", len(blocks))
	}
	if len(blocks[0].Segments) != 1 {
		t.Fatalf("Expected 1 segment, got %d", len(blocks[0].Segments))
	}

	segment := blocks[0].Segments[0]
	var tokensText []string
	for _, tok := range segment {
		tokensText = append(tokensText, tok.Text)
	}

	expectedTokens := []string{"echo", "arg1", "arg2"}
	if len(tokensText) != len(expectedTokens) {
		t.Fatalf("Expected tokens %v, got %v", expectedTokens, tokensText)
	}
	for i, exp := range expectedTokens {
		if tokensText[i] != exp {
			t.Errorf("Token %d: expected %q, got %q", i, exp, tokensText[i])
		}
	}
}

func TestVariadicImportExpansionZeroArgs(t *testing.T) {
	// Test expanding {args[2:5]} when 2 args are provided (0 args selected)
	p := testParser(`
		(snippet) {
			echo {args[2:5]}
		}
		http://example.com {
			import snippet arg1 arg2
		}
	`)
	blocks, err := p.parseAll()
	if err != nil {
		t.Fatalf("Unexpected error during parsing: %v", err)
	}
	if len(blocks) != 1 {
		t.Fatalf("Expected 1 block, got %d", len(blocks))
	}
	if len(blocks[0].Segments) != 1 {
		t.Fatalf("Expected 1 segment, got %d", len(blocks[0].Segments))
	}

	segment := blocks[0].Segments[0]
	var tokensText []string
	for _, tok := range segment {
		tokensText = append(tokensText, tok.Text)
	}

	expectedTokens := []string{"echo"}
	if len(tokensText) != len(expectedTokens) {
		t.Fatalf("Expected tokens %v, got %v", expectedTokens, tokensText)
	}
	if tokensText[0] != "echo" {
		t.Errorf("Expected token %q, got %q", "echo", tokensText[0])
	}
}
