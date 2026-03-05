package transport

import (
	"testing"
)

func TestParseAddressHostPort(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		typeName string
		host     string
		port     uint16
		wantErr  bool
	}{
		{"ipv4 hostname", "tcp:localhost:8080", "tcp", "localhost", 8080, false},
		{"ipv4 ip", "tcp:127.0.0.1:8080", "tcp", "127.0.0.1", 8080, false},
		{"ipv6 loopback", "tcp:[::1]:8080", "tcp", "::1", 8080, false},
		{"ipv6 full", "tcp:[fe80::1]:443", "tcp", "fe80::1", 443, false},
		{"wrong prefix", "udp:localhost:8080", "tcp", "", 0, true},
		{"missing port", "tcp:localhost", "tcp", "", 0, true},
		{"invalid port", "tcp:localhost:abc", "tcp", "", 0, true},
		{"port too large", "tcp:localhost:99999", "tcp", "", 0, true},
		{"empty string", "", "tcp", "", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, err := ParseAddressHostPort(tt.input, tt.typeName)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseAddressHostPort(%q, %q) expected error, got nil", tt.input, tt.typeName)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseAddressHostPort(%q, %q) unexpected error: %v", tt.input, tt.typeName, err)
				return
			}
			if host != tt.host {
				t.Errorf("ParseAddressHostPort(%q, %q) host = %q, want %q", tt.input, tt.typeName, host, tt.host)
			}
			if port != tt.port {
				t.Errorf("ParseAddressHostPort(%q, %q) port = %d, want %d", tt.input, tt.typeName, port, tt.port)
			}
		})
	}
}

func TestHostPortString(t *testing.T) {
	tests := []struct {
		name string
		host string
		port uint16
		want string
	}{
		{"ipv4 hostname", "localhost", 8080, "localhost:8080"},
		{"ipv4 ip", "127.0.0.1", 8080, "127.0.0.1:8080"},
		{"ipv6 loopback", "::1", 8080, "[::1]:8080"},
		{"ipv6 full", "fe80::1", 443, "[fe80::1]:443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HostPortString(tt.host, tt.port)
			if got != tt.want {
				t.Errorf("HostPortString(%q, %d) = %q, want %q", tt.host, tt.port, got, tt.want)
			}
		})
	}
}
