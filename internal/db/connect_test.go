package db

import (
	"errors"
	"testing"
)

func TestParseConfigRejectsNonTLSDSNs(t *testing.T) {
	insecure := []struct {
		name string
		dsn  string
	}{
		{"sslmode disable", "postgres://u:p@localhost:5432/kura?sslmode=disable"},
		{"sslmode allow", "postgres://u:p@localhost:5432/kura?sslmode=allow"},
		{"sslmode prefer", "postgres://u:p@localhost:5432/kura?sslmode=prefer"},
		{"no sslmode (defaults to prefer)", "postgres://u:p@localhost:5432/kura"},
		{"keyword form, sslmode disable", "host=localhost user=u password=p dbname=kura sslmode=disable"},
	}
	for _, tt := range insecure {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseConfig(tt.dsn)
			if !errors.Is(err, ErrInsecureDSN) {
				t.Fatalf("ParseConfig(%q) error = %v, want ErrInsecureDSN", tt.dsn, err)
			}
		})
	}
}

func TestParseConfigAcceptsTLSRequiredDSNs(t *testing.T) {
	secure := []struct {
		name string
		dsn  string
	}{
		{"sslmode require", "postgres://u:p@localhost:5432/kura?sslmode=require"},
		{"sslmode verify-ca", "postgres://u:p@localhost:5432/kura?sslmode=verify-ca"},
		{"sslmode verify-full", "postgres://u:p@localhost:5432/kura?sslmode=verify-full"},
		{"keyword form, sslmode require", "host=localhost user=u password=p dbname=kura sslmode=require"},
	}
	for _, tt := range secure {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ParseConfig(tt.dsn)
			if err != nil {
				t.Fatalf("ParseConfig(%q) unexpected error: %v", tt.dsn, err)
			}
			if cfg == nil {
				t.Fatalf("ParseConfig(%q) returned nil config", tt.dsn)
			}
		})
	}
}

func TestParseConfigRejectsMalformedDSN(t *testing.T) {
	_, err := ParseConfig("://not a dsn")
	if err == nil {
		t.Fatal("ParseConfig of malformed DSN returned nil error")
	}
	if errors.Is(err, ErrInsecureDSN) {
		t.Fatalf("ParseConfig of malformed DSN = ErrInsecureDSN, want a parse error")
	}
}
