package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/bensyverson/kura/internal/clio"
)

// TestCLIErrorPrefixesAreGreppable pins the agent-facing error contract
// at the CLI level: every error a kura command can return starts with a
// stable, machine-matchable `<area>: ` first line (whoami / login /
// profiles), and resolves to a specific Kind in the taxonomy. This is
// the same regression-surface pattern as job's
// `...ErrorPrefixIsGreppable` tests — if a refactor breaks a prefix or
// drops a classification, this test fails before the agent sees it.
//
// The internal/clio tests cover the constructors in isolation; this
// test covers the actual call sites by running the root command with
// inputs that drive each error path.
func TestCLIErrorPrefixesAreGreppable(t *testing.T) {
	cases := []struct {
		name       string
		args       []string
		env        map[string]string
		homeIsTemp bool
		wantPrefix string
		wantKind   clio.Kind
		wantInMsg  []string
	}{
		{
			name:       "whoami --local with no --as is a usage error",
			args:       []string{"whoami", "--local"},
			env:        map[string]string{"KURA_FIRM_DOMAIN": "firm.example"},
			wantPrefix: "whoami: ",
			wantKind:   clio.KindUsage,
			wantInMsg:  []string{"--as"},
		},
		{
			name:       "whoami --local with a malformed --as is a usage error",
			args:       []string{"whoami", "--local", "--as", "notanemail"},
			env:        map[string]string{"KURA_FIRM_DOMAIN": "firm.example"},
			wantPrefix: "whoami: ",
			wantKind:   clio.KindUsage,
			wantInMsg:  []string{"--as", "notanemail"},
		},
		{
			name:       "whoami --local with no KURA_FIRM_DOMAIN is a usage error",
			args:       []string{"whoami", "--local", "--as", "alex@firm.example"},
			env:        map[string]string{"KURA_FIRM_DOMAIN": ""},
			wantPrefix: "whoami: ",
			wantKind:   clio.KindUsage,
			wantInMsg:  []string{"KURA_FIRM_DOMAIN"},
		},
		{
			name:       "whoami remote with no server config is a usage error",
			args:       []string{"whoami"},
			homeIsTemp: true,
			wantPrefix: "whoami: ",
			wantKind:   clio.KindUsage,
			wantInMsg:  []string{"--server", "--client", "kura login"},
		},
		{
			name:       "whoami remote with --server but no cached credential is an auth error",
			args:       []string{"whoami", "--server", "https://kura.example"},
			homeIsTemp: true,
			wantPrefix: "login: ",
			wantKind:   clio.KindAuth,
			wantInMsg:  []string{"no cached credential", "kura login"},
		},
		{
			name:       "login with no --server is a usage error",
			args:       []string{"login"},
			wantPrefix: "login: ",
			wantKind:   clio.KindUsage,
			wantInMsg:  []string{"--server"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			if c.homeIsTemp {
				// HOME drives os.UserConfigDir on darwin and linux;
				// pointing it at a tempdir keeps the test from touching
				// the developer's real config.
				t.Setenv("HOME", t.TempDir())
				t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			}
			_, _, err := runRoot(t, c.args...)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			first := strings.SplitN(err.Error(), "\n", 2)[0]
			if !strings.HasPrefix(first, c.wantPrefix) {
				t.Errorf("first line %q does not start with %q", first, c.wantPrefix)
			}
			var ce *clio.Error
			if !errors.As(err, &ce) {
				t.Fatalf("error %T is not a *clio.Error — taxonomy was dropped on the way out", err)
			}
			if ce.Kind != c.wantKind {
				t.Errorf("Kind = %v, want %v", ce.Kind, c.wantKind)
			}
			for _, w := range c.wantInMsg {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not contain %q (the agent needs this fix-hint to act)", err, w)
				}
			}
		})
	}
}

// TestWhoamiOutputIsMaskingInvariant pins criterion tb7 at the
// command-call level: the same principal rendered through `kura
// whoami` once as Markdown and once as --json shows the same field
// values. Format is a presentation choice; visibility is the core's
// call. (The shared layer is also covered in
// internal/clio/render_test.go.)
func TestWhoamiOutputIsMaskingInvariant(t *testing.T) {
	t.Setenv("KURA_FIRM_DOMAIN", "firm.example")
	t.Setenv("KURA_CLIENT_DOMAINS", "client.example")

	md, _, err := runRoot(t, "whoami", "--local", "--as", "alex@firm.example")
	if err != nil {
		t.Fatalf("whoami markdown: %v", err)
	}
	js, _, err := runRoot(t, "whoami", "--local", "--as", "alex@firm.example", "--json")
	if err != nil {
		t.Fatalf("whoami json: %v", err)
	}

	// Both renderings of the same principal must show the same identity
	// values. The renderer never adds a field one format hides.
	for _, want := range []string{"alex@firm.example", "consultant", "firm.example"} {
		if !strings.Contains(md.String(), want) {
			t.Errorf("markdown view missing %q: %s", want, md.String())
		}
		if !strings.Contains(js.String(), want) {
			t.Errorf("json view missing %q: %s", want, js.String())
		}
	}
}
