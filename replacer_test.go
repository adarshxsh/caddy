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
	"sync"
	"testing"
	"time"
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

func TestFileReplacementStatCache(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "caddy_file_cache_test_*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	content1 := "initial content\n"
	if _, err := tmpFile.WriteString(content1); err != nil {
		t.Fatalf("failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	defaultFileCache.clear()
	rep := NewReplacer()

	fileKey := "file." + tmpFile.Name()

	val1, ok1 := rep.Get(fileKey)
	if !ok1 || val1 != "initial content" {
		t.Fatalf("expected 'initial content', got val: %v, ok: %v", val1, ok1)
	}

	// Repeated fetch should return cached content
	val2, ok2 := rep.Get(fileKey)
	if !ok2 || val2 != "initial content" {
		t.Fatalf("expected cached 'initial content', got val: %v, ok: %v", val2, ok2)
	}

	// Overwrite file on disk and modify mtime
	newContent := "modified content\n"
	if err := os.WriteFile(tmpFile.Name(), []byte(newContent), 0644); err != nil {
		t.Fatalf("failed to overwrite temp file: %v", err)
	}

	// In case filesystem mtime resolution is coarse (e.g. 1s), adjust mtime into future
	futureTime := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(tmpFile.Name(), futureTime, futureTime)

	val3, ok3 := rep.Get(fileKey)
	if !ok3 || val3 != "modified content" {
		t.Fatalf("expected updated 'modified content', got val: %v, ok: %v", val3, ok3)
	}
}

func TestFileCacheBoundedCapacity(t *testing.T) {
	fc := newFileCache(2)
	now := time.Now()

	fc.set("file1.txt", "content1", now, 10)
	fc.set("file2.txt", "content2", now, 10)

	if v, ok := fc.get("file1.txt", now, 10); !ok || v != "content1" {
		t.Errorf("expected file1.txt content1, got %v, %v", v, ok)
	}

	// Adding file3.txt when capacity is 2 triggers eviction
	fc.set("file3.txt", "content3", now, 10)

	fc.mu.RLock()
	count := len(fc.items)
	fc.mu.RUnlock()

	if count > 2 {
		t.Errorf("expected max entries 2, got %d", count)
	}

	if v, ok := fc.get("file3.txt", now, 10); !ok || v != "content3" {
		t.Errorf("expected file3.txt content3, got %v, %v", v, ok)
	}
}

func TestWorkingDirOnce(t *testing.T) {
	wd1 := getWorkingDir()
	if wd1 == "" {
		t.Errorf("expected non-empty working directory")
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wd := getWorkingDir()
			if wd != wd1 {
				t.Errorf("expected working directory %s, got %s", wd1, wd)
			}
		}()
	}
	wg.Wait()
}

func TestReadFileIntoBufferPool(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "caddy_buf_pool_test_*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	expectedContent := "pooled buffer test content\r\n"
	if _, err := tmpFile.WriteString(expectedContent); err != nil {
		t.Fatalf("failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	bytesRead, err := readFileIntoBuffer(tmpFile.Name(), 1024)
	if err != nil {
		t.Fatalf("readFileIntoBuffer failed: %v", err)
	}

	if string(bytesRead) != expectedContent {
		t.Fatalf("expected '%s', got '%s'", expectedContent, string(bytesRead))
	}
}

func BenchmarkFileReplacer(b *testing.B) {
	tmpDir := b.TempDir()
	tmpFile := filepath.Join(tmpDir, "bench.txt")
	if err := os.WriteFile(tmpFile, []byte("bench content\n"), 0644); err != nil {
		b.Fatalf("failed to write tmp file: %v", err)
	}

	rep := NewReplacer()
	ph := "{file." + tmpFile + "}"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rep.ReplaceAll(ph, "")
	}
}
