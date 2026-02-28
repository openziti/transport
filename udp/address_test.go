package udp

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
		{"ipv4 hostname", "udp:localhost:8080", "udp:localhost:8080", false},
		{"ipv4 ip", "udp:127.0.0.1:8080", "udp:127.0.0.1:8080", false},
		{"ipv6 loopback", "udp:[::1]:8080", "udp:[::1]:8080", false},
		{"ipv6 full", "udp:[fe80::1]:443", "udp:[fe80::1]:443", false},
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
