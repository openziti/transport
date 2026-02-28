package dtls

import (
	"testing"
)

func TestParseAndString(t *testing.T) {
	parser := AddressParser{}

	tests := []struct {
		name     string
		input    string
		want     string
		wantHost string
		wantPort uint16
		wantErr  bool
	}{
		{"ipv4 ip", "dtls:127.0.0.1:8080", "dtls:127.0.0.1:8080", "127.0.0.1", 8080, false},
		{"ipv6 loopback", "dtls:[::1]:8080", "dtls:[::1]:8080", "::1", 8080, false},
		{"ipv6 full", "dtls:[fe80::1]:443", "dtls:[fe80::1]:443", "fe80::1", 443, false},
		{"ipv6 all zeros", "dtls:[::]:9090", "dtls:[::]:9090", "::", 9090, false},
		{"wrong prefix", "tcp:127.0.0.1:8080", "", "", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parser.Parse(tt.input)
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
			addr := result.(*address)
			if addr.err != nil {
				t.Errorf("Parse(%q) unexpected addr error: %v", tt.input, addr.err)
				return
			}
			if got := addr.String(); got != tt.want {
				t.Errorf("Parse(%q).String() = %q, want %q", tt.input, got, tt.want)
			}
			if got := addr.Hostname(); got != tt.wantHost {
				t.Errorf("Parse(%q).Hostname() = %q, want %q", tt.input, got, tt.wantHost)
			}
			if got := addr.Port(); got != tt.wantPort {
				t.Errorf("Parse(%q).Port() = %d, want %d", tt.input, got, tt.wantPort)
			}
		})
	}
}
