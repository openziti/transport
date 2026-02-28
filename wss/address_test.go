package wss

import (
	"testing"
)

func TestParseAndString(t *testing.T) {
	parser := AddressParser{}

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"ipv4 hostname", "wss:localhost:8080", "wss:localhost:8080", false},
		{"ipv4 ip", "wss:127.0.0.1:8080", "wss:127.0.0.1:8080", false},
		{"ipv6 loopback", "wss:[::1]:8080", "wss:[::1]:8080", false},
		{"ipv6 full", "wss:[fe80::1]:443", "wss:[fe80::1]:443", false},
		{"wrong prefix", "tcp:localhost:8080", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := parser.Parse(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Parse(%q) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("Parse(%q) unexpected error: %v", tt.input, err)
				return
			}
			if got := addr.String(); got != tt.want {
				t.Errorf("Parse(%q).String() = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
