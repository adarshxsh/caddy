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

func BenchmarkFileReplacer(b *testing.B) {
	tmpDir := b.TempDir()
	tmpFile := filepath.Join(tmpDir, "bench.txt")
	if err := os.WriteFile(tmpFile, []byte("bench content\n"), 0644); err != nil {
		b.Fatalf("failed to write tmp file: %v", err)
	}

	rep := NewReplacer()
	ph := "{file." + tmpFile + "}"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rep.ReplaceAll(ph, "")
	}
}

func testReplacer() Replacer {
	return Replacer{
		providers: make([]replacementProvider, 0),
		static:    make(map[string]any),
		mapMutex:  &sync.RWMutex{},
	}
}

func TestFileReplacementCacheHitAndExpiry(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.txt")

	if err := os.WriteFile(tmpFile, []byte("hello v1\n"), 0644); err != nil {
		t.Fatalf("failed to write tmp file: %v", err)
	}

	provider := fileReplacementProvider{
		cache: newFileCache(10, 100*time.Millisecond),
	}

	// First lookup (cache miss)
	val, ok := provider.replace("file." + tmpFile)
	if !ok || val != "hello v1" {
		t.Fatalf("expected 'hello v1', got %v (ok=%v)", val, ok)
	}

	// Update file on disk
	if err := os.WriteFile(tmpFile, []byte("hello v2\n"), 0644); err != nil {
		t.Fatalf("failed to update tmp file: %v", err)
	}

	// Second lookup immediately (cache hit)
	val2, ok2 := provider.replace("file." + tmpFile)
	if !ok2 || val2 != "hello v1" {
		t.Fatalf("expected cached 'hello v1', got %v (ok=%v)", val2, ok2)
	}

	// Wait for TTL to expire
	time.Sleep(120 * time.Millisecond)

	// Third lookup after TTL expiry (cache miss)
	val3, ok3 := provider.replace("file." + tmpFile)
	if !ok3 || val3 != "hello v2" {
		t.Fatalf("expected updated 'hello v2' after TTL expiry, got %v (ok=%v)", val3, ok3)
	}
}

func TestFileReplacementCacheBoundedCapacity(t *testing.T) {
	maxEntries := 5
	cache := newFileCache(maxEntries, 10*time.Second)

	for i := 1; i <= 10; i++ {
		key := fmt.Sprintf("/path/file%d.txt", i)
		cache.set(key, fmt.Sprintf("content%d", i))
		cache.mu.RLock()
		itemCount := len(cache.items)
		cache.mu.RUnlock()
		if itemCount > maxEntries {
			t.Fatalf("cache size %d exceeded maxEntries %d after inserting %s", itemCount, maxEntries, key)
		}
	}

	cache.mu.RLock()
	finalCount := len(cache.items)
	cache.mu.RUnlock()
	if finalCount != maxEntries {
		t.Fatalf("expected final cache count %d, got %d", maxEntries, finalCount)
	}

	if val, ok := cache.get("/path/file10.txt"); !ok || val != "content10" {
		t.Fatalf("expected content10 for file10.txt, got %v (ok=%v)", val, ok)
	}
}

func TestFileReplacementCacheConcurrency(t *testing.T) {
	provider := fileReplacementProvider{
		cache: newFileCache(20, 50*time.Millisecond),
	}

	tmpDir := t.TempDir()
	var files []string
	for i := 0; i < 10; i++ {
		fPath := filepath.Join(tmpDir, fmt.Sprintf("file%d.txt", i))
		_ = os.WriteFile(fPath, []byte(fmt.Sprintf("data-%d", i)), 0644)
		files = append(files, fPath)
	}

	var wg sync.WaitGroup
	for g := 0; g < 20; g++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for iter := 0; iter < 100; iter++ {
				fPath := files[(goroutineID+iter)%len(files)]
				val, ok := provider.replace("file." + fPath)
				if !ok {
					t.Errorf("expected ok for file %s", fPath)
				}
				_ = val
			}
		}(g)
	}
	wg.Wait()
}

func TestFileReplacementErrorHandling(t *testing.T) {
	provider := fileReplacementProvider{
		cache: newFileCache(10, 1*time.Second),
	}

	nonExistentPath := filepath.Join(t.TempDir(), "does_not_exist.txt")
	val, ok := provider.replace("file." + nonExistentPath)
	if !ok {
		t.Fatalf("expected ok=true for file replacement error handling, got ok=%v", ok)
	}
	if val != nil {
		t.Fatalf("expected nil value for missing file, got %v", val)
	}
}

