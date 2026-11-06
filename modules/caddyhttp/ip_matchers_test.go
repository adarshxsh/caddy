package caddyhttp

import (
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
)

func TestMatchClientIP_MissingClientIPVar(t *testing.T) {
	matcher := MatchClientIP{
		Ranges: []string{"192.168.1.0/24"},
		logger: zap.NewNop(),
	}

	req := httptest.NewRequest("GET", "/", nil)
	// req context has no ClientIPVarKey set

	matched, err := matcher.MatchWithError(req)
	if err != nil {
		t.Fatalf("expected no error from MatchWithError, got: %v", err)
	}
	if matched {
		t.Error("expected matched to be false when ClientIPVarKey is missing")
	}
}
