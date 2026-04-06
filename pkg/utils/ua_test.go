package utils

import (
	"strings"
	"testing"
)

func TestParseUA(t *testing.T) {
	tests := []struct {
		name     string
		ua       string
		contains []string
	}{
		{
			name: "mobile safari",
			ua:   "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15A372 Safari/604.1",
			contains: []string{
				"mobile",
				"Safari",
				"iOS",
			},
		},
		{
			name: "desktop chrome",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
			contains: []string{
				"browser",
				"Chrome",
				"Windows",
			},
		},
		{
			name: "bot curl",
			ua:   "curl/7.64.1",
			contains: []string{
				"bot",
				"curl",
			},
		},
		{
			name: "empty ua",
			ua:   "",
			contains: []string{
				"browser",
				"unknown",
			},
		},
		{
			name: "long ua trimmed",
			ua:   strings.Repeat("A", 500),
			contains: []string{
				"browser",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseUA(tt.ua)

			for _, expect := range tt.contains {
				if !strings.Contains(strings.ToLower(result), strings.ToLower(expect)) {
					t.Errorf("expected result to contain %s, got %s", expect, result)
				}
			}
		})
	}
}
func TestIsBotUA(t *testing.T) {
	tests := []struct {
		ua       string
		expected bool
	}{
		{"curl/7.64.1", true},
		{"Googlebot/2.1", true},
		{"Mozilla/5.0 Chrome/120", false},
	}

	for _, tt := range tests {
		result := isBotUA(tt.ua)
		if result != tt.expected {
			t.Errorf("expected %v, got %v", tt.expected, result)
		}
	}
}

func TestFormatBrowser(t *testing.T) {
	ua := ParseUA("Mozilla/5.0 Chrome/120.0.0.0")

	if !strings.Contains(ua, "Chrome") {
		t.Errorf("expected Chrome in result, got %s", ua)
	}
}

func BenchmarkParseUA(b *testing.B) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"

	for i := 0; i < b.N; i++ {
		ParseUA(ua)
	}
}