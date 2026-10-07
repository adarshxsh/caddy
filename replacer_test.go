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

package caddy

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func TestReplacer(t *testing.T) {
	type testCase struct {
		input, expect, empty string
	}

	rep := testReplacer()

	// ReplaceAll
	for i, tc := range []testCase{
		{
			input:  "{",
			expect: "{",
		},
		{
			input:  `\{`,
			expect: `{`,
		},
		{
			input:  "foo{",
			expect: "foo{",
		},
		{
			input:  `foo\{`,
			expect: `foo{`,
		},
		{
			input:  "foo{bar",
			expect: "foo{bar",
		},
		{
			input:  `foo\{bar`,
			expect: `foo{bar`,
		},
		{
			input:  "foo{bar}",
			expect: "foo",
		},
		{
			input:  `foo\{bar\}`,
			expect: `foo{bar}`,
		},
		{
			input:  "}",
			expect: "}",
		},
		{
			input:  `\}`,
			expect: `}`,
		},
		{
			input:  "{}",
			expect: "",
		},
		{
			input:  `\{\}`,
			expect: `{}`,
		},
		{
			input:  `{"json": "object"}`,
			expect: "",
		},
		{
			input:  `\{"json": "object"}`,
			expect: `{"json": "object"}`,
		},
		{
			input:  `\{"json": "object"\}`,
			expect: `{"json": "object"}`,
		},
		{
			input:  `\{"json": "object{bar}"\}`,
			expect: `{"json": "object"}`,
		},
		{
			input:  `\{"json": \{"nested": "object"\}\}`,
			expect: `{"json": {"nested": "object"}}`,
		},
		{
			input:  `\{"json": \{"nested": "{bar}"\}\}`,
			expect: `{"json": {"nested": ""}}`,
		},
		{
			input:  `pre \{"json": \{"nested": "{bar}"\}\}`,
			expect: `pre {"json": {"nested": ""}}`,
		},
		{
			input:  `\{"json": \{"nested": "{bar}"\}\} post`,
			expect: `{"json": {"nested": ""}} post`,
		},
		{
			input:  `pre \{"json": \{"nested": "{bar}"\}\} post`,
			expect: `pre {"json": {"nested": ""}} post`,
		},
		{
			input:  `{{`,
			expect: "{{",
		},
		{
			input:  `{{}`,
			expect: "",
		},
		{
			input:  `{"json": "object"\}`,
			expect: "",
		},
		{
			input:  `{unknown}`,
			empty:  "-",
			expect: "-",
		},
		{
			input:  `back\slashes`,
			expect: `back\slashes`,
		},
		{
			input:  `double back\\slashes`,
			expect: `double back\\slashes`,
		},
		{
			input:  `placeholder {with \{ brace} in name`,
			expect: `placeholder  in name`,
		},
		{
			input:  `placeholder {with \} brace} in name`,
			expect: `placeholder  in name`,
		},
		{
			input:  `placeholder {with \} \} braces} in name`,
			expect: `placeholder  in name`,
		},
		{
			input:  `\{'group':'default','max_age':3600,'endpoints':[\{'url':'https://some.domain.local/a/d/g'\}],'include_subdomains':true\}`,
			expect: `{'group':'default','max_age':3600,'endpoints':[{'url':'https://some.domain.local/a/d/g'}],'include_subdomains':true}`,
		},
		{
			input:  `{}{}{}{\\\\}\\\\`,
			expect: `{\\\}\\\\`,
		},
		{
			input:  string([]byte{0x26, 0x00, 0x83, 0x7B, 0x84, 0x07, 0x5C, 0x7D, 0x84}),
			expect: string([]byte{0x26, 0x00, 0x83, 0x7B, 0x84, 0x07, 0x7D, 0x84}),
		},
		{
			input:  `\\}`,
			expect: `\}`,
		},
	} {
		actual := rep.ReplaceAll(tc.input, tc.empty)
		if actual != tc.expect {
			t.Errorf("Test %d: '%s': expected '%s' but got '%s'",
				i, tc.input, tc.expect, actual)
		}
	}
}

func TestNestedReplacer(t *testing.T) {
	os.Setenv("VAR_example.com", "matched_env_value")
	os.Setenv("VAR_{prefix}_example.com", "escaped_brace_success")
	defer func() {
		os.Unsetenv("VAR_example.com")
		os.Unsetenv("VAR_{prefix}_example.com")
	}()

	rep := NewReplacer()
	rep.Set("http.request.host", "example.com")
	rep.Set("c", "3")
	rep.Set("b_3", "2")
	rep.Set("a_2", "1")
	rep.Set("prefix_1", "deep_success")

	t.Run("basic nested placeholder", func(t *testing.T) {
		input := "{env.VAR_{http.request.host}}"
		expected := "matched_env_value"
		actual := rep.ReplaceAll(input, "")
		if actual != expected {
			t.Errorf("expected '%s', got '%s'", expected, actual)
		}
	})

	t.Run("nested placeholder in string context", func(t *testing.T) {
		input := "Header: {env.VAR_{http.request.host}} / path"
		expected := "Header: matched_env_value / path"
		actual := rep.ReplaceAll(input, "")
		if actual != expected {
			t.Errorf("expected '%s', got '%s'", expected, actual)
		}
	})

	t.Run("deeply nested placeholders", func(t *testing.T) {
		input := "{prefix_{a_{b_{c}}}}"
		expected := "deep_success"
		actual := rep.ReplaceAll(input, "")
		if actual != expected {
			t.Errorf("expected '%s', got '%s'", expected, actual)
		}
	})

	t.Run("escaped braces inside nested placeholders", func(t *testing.T) {
		input := "{env.VAR_\\{prefix\\}_{http.request.host}}"
		expected := "escaped_brace_success"
		actual := rep.ReplaceAll(input, "")
		if actual != expected {
			t.Errorf("expected '%s', got '%s'", expected, actual)
		}
	})

	t.Run("error on unknown inner placeholder in ReplaceOrErr", func(t *testing.T) {
		input := "{env.VAR_{unknown_inner_key}}"
		_, err := rep.ReplaceOrErr(input, false, true)
		if err == nil {
			t.Errorf("expected error for unknown inner placeholder, got nil")
		}
	})

	t.Run("recursion depth limit exceeded", func(t *testing.T) {
		// Construct 102 levels of nested opening braces
		var buf strings.Builder
		for i := 0; i < 102; i++ {
			buf.WriteString("{a.")
		}
		buf.WriteString("v")
		for i := 0; i < 102; i++ {
			buf.WriteString("}")
		}
		_, err := rep.ReplaceOrErr(buf.String(), false, true)
		if err == nil {
			t.Errorf("expected error for exceeding recursion depth limit, got nil")
		}
	})
}

func TestReplacerSet(t *testing.T) {
	rep := testReplacer()

	for _, tc := range []struct {
		variable string
		value    any
	}{
		{
			variable: "test1",
			value:    "val1",
		},
		{
			variable: "asdf",
			value:    "123",
		},
		{
			variable: "numbers",
			value:    123.456,
		},
		{
			variable: "äöü",
			value:    "öö_äü",
		},
		{
			variable: "with space",
			value:    "space value",
		},
		{
			variable: "1",
			value:    "test-123",
		},
		{
			variable: "mySuper_IP",
			value:    "1.2.3.4",
		},
		{
			variable: "testEmpty",
			value:    "",
		},
	} {
		rep.Set(tc.variable, tc.value)

		// test if key is added
		if val, ok := rep.static[tc.variable]; ok {
			if val != tc.value {
				t.Errorf("Expected value '%s' for key '%s' got '%s'", tc.value, tc.variable, val)
			}
		} else {
			t.Errorf("Expected existing key '%s' found nothing", tc.variable)
		}
	}

	// test if all keys are still there (by length)
	length := len(rep.static)
	if len(rep.static) != 8 {
		t.Errorf("Expected length '%v' got '%v'", 7, length)
	}
}

func TestReplacerReplaceKnown(t *testing.T) {
	rep := Replacer{
		mapMutex: &sync.RWMutex{},
		providers: []replacementProvider{
			// split our possible vars to two functions (to test if both functions are called)
			ReplacerFunc(func(key string) (val any, ok bool) {
				switch key {
				case "test1":
					return "val1", true
				case "asdf":
					return "123", true
				case "äöü":
					return "öö_äü", true
				case "with space":
					return "space value", true
				default:
					return "NOOO", false
				}
			}),
			ReplacerFunc(func(key string) (val any, ok bool) {
				switch key {
				case "1":
					return "test-123", true
				case "mySuper_IP":
					return "1.2.3.4", true
				case "testEmpty":
					return "", true
				default:
					return "NOOO", false
				}
			}),
		},
	}

	for _, tc := range []struct {
		testInput string
		expected  string
	}{
		{
			// test vars without space
			testInput: "{test1}{asdf}{äöü}{1}{with space}{mySuper_IP}",
			expected:  "val1123öö_äütest-123space value1.2.3.4",
		},
		{
			// test vars with space
			testInput: "{test1} {asdf} {äöü} {1} {with space} {mySuper_IP} ",
			expected:  "val1 123 öö_äü test-123 space value 1.2.3.4 ",
		},
		{
			// test with empty val
			testInput: "{test1} {testEmpty} {asdf} {1} ",
			expected:  "val1 EMPTY 123 test-123 ",
		},
		{
			// test vars with not finished placeholders
			testInput: "{te{test1}{as{{df{1}",
			expected:  "{teval1{as{{dftest-123",
		},
		{
			// test with non existing vars
			testInput: "{test1} {nope} {1} ",
			expected:  "val1 {nope} test-123 ",
		},
	} {
		actual := rep.ReplaceKnown(tc.testInput, "EMPTY")

		// test if all are replaced as expected
		if actual != tc.expected {
			t.Errorf("Expected '%s' got '%s' for '%s'", tc.expected, actual, tc.testInput)
		}
	}
}

func TestReplacerDelete(t *testing.T) {
	rep := Replacer{
		mapMutex: &sync.RWMutex{},
		static: map[string]any{
			"key1": "val1",
			"key2": "val2",
			"key3": "val3",
			"key4": "val4",
		},
	}

	startLen := len(rep.static)

	toDel := []string{
		"key2", "key4",
	}

	for _, key := range toDel {
		rep.Delete(key)

		// test if key is removed from static map
		if _, ok := rep.static[key]; ok {
			t.Errorf("Expected '%s' to be removed. It is still in static map.", key)
		}
	}

	// check if static slice is smaller
	expected := startLen - len(toDel)
	actual := len(rep.static)
	if len(rep.static) != expected {
		t.Errorf("Expected length '%v' got length '%v'", expected, actual)
	}
}

func TestReplacerMap(t *testing.T) {
	rep := testReplacer()

	for i, tc := range []ReplacerFunc{
		func(key string) (val any, ok bool) {
			return "", false
		},
		func(key string) (val any, ok bool) {
			return "", false
		},
	} {
		rep.Map(tc)

		// test if function (which listens on specific key) is added by checking length
		if len(rep.providers) == i+1 {
			// check if the last function is the one we just added
			pTc := fmt.Sprintf("%p", tc)
			pRep := fmt.Sprintf("%p", rep.providers[i])
			if pRep != pTc {
				t.Errorf("Expected func pointer '%s' got '%s'", pTc, pRep)
			}
		} else {
			t.Errorf("Expected providers length '%v' got length '%v'", i+1, len(rep.providers))
		}
	}
}

func TestReplacerNew(t *testing.T) {
	repl := NewReplacer()

	if len(repl.providers) != 3 {
		t.Errorf("Expected providers length '%v' got length '%v'", 3, len(repl.providers))
	}

	// test if default global replacements are added as the first provider
	hostname, _ := os.Hostname()
	wd, _ := os.Getwd()
	os.Setenv("CADDY_REPLACER_TEST", "envtest")
	defer os.Setenv("CADDY_REPLACER_TEST", "")

	for _, tc := range []struct {
		variable string
		value    string
	}{
		{
			variable: "system.hostname",
			value:    hostname,
		},
		{
			variable: "system.slash",
			value:    string(filepath.Separator),
		},
		{
			variable: "system.os",
			value:    runtime.GOOS,
		},
		{
			variable: "system.arch",
			value:    runtime.GOARCH,
		},
		{
			variable: "system.wd",
			value:    wd,
		},
		{
			variable: "env.CADDY_REPLACER_TEST",
			value:    "envtest",
		},
	} {
		if val, ok := repl.providers[0].replace(tc.variable); ok {
			if val != tc.value {
				t.Errorf("Expected value '%s' for key '%s' got '%s'", tc.value, tc.variable, val)
			}
		} else {
			t.Errorf("Expected key '%s' to be recognized by first provider", tc.variable)
		}
	}

	// test if file provider is added as the second provider
	for _, tc := range []struct {
		variable string
		value    string
	}{
		{
			variable: "file.caddytest/integration/testdata/foo.txt",
			value:    "foo",
		},
		{
			variable: "file.caddytest/integration/testdata/foo_with_trailing_newline.txt",
			value:    "foo",
		},
		{
			variable: "file.caddytest/integration/testdata/foo_with_multiple_trailing_newlines.txt",
			value:    "foo" + getEOL(),
		},
	} {
		if val, ok := repl.providers[1].replace(tc.variable); ok {
			if val != tc.value {
				t.Errorf("Expected value '%s' for key '%s' got '%s'", tc.value, tc.variable, val)
			}
		} else {
			t.Errorf("Expected key '%s' to be recognized by second provider", tc.variable)
		}
	}
}

func getEOL() string {
	if os.PathSeparator == '\\' {
		return "\r\n" // Windows EOL
	}
	return "\n" // Unix and modern macOS EOL
}

func TestReplacerNewWithoutFile(t *testing.T) {
	repl := NewReplacer().WithoutFile()

	for _, tc := range []struct {
		variable string
		value    string
		notFound bool
	}{
		{
			variable: "file.caddytest/integration/testdata/foo.txt",
			notFound: true,
		},
		{
			variable: "system.os",
			value:    runtime.GOOS,
		},
	} {
		if val, ok := repl.Get(tc.variable); ok && !tc.notFound {
			if val != tc.value {
				t.Errorf("Expected value '%s' for key '%s' got '%s'", tc.value, tc.variable, val)
			}
		} else if !tc.notFound {
			t.Errorf("Expected key '%s' to be recognized", tc.variable)
		}
	}
}

func BenchmarkReplacer(b *testing.B) {
	type testCase struct {
		name, input, empty string
	}

	rep := testReplacer()
	rep.Set("str", "a string")
	rep.Set("int", 123.456)

	for _, bm := range []testCase{
		{
			name:  "no placeholder",
			input: `simple string`,
		},
		{
			name:  "string replacement",
			input: `str={str}`,
		},
		{
			name:  "int replacement",
			input: `int={int}`,
		},
		{
			name:  "placeholder",
			input: `{"json": "object"}`,
		},
		{
			name:  "escaped placeholder",
			input: `\{"json": \{"nested": "{bar}"\}\}`,
		},
	} {
		b.Run(bm.name, func(b *testing.B) {
			for b.Loop() {
				rep.ReplaceAll(bm.input, bm.empty)
			}
		})
	}
}

func testReplacer() Replacer {
	return Replacer{
		providers: make([]replacementProvider, 0),
		static:    make(map[string]any),
		mapMutex:  &sync.RWMutex{},
	}
}
