package cedar

import (
	"strings"
	"testing"

	cedarengine "github.com/cedar-policy/cedar-go"
)

// MdQ: the IR compiles to valid Cedar policy text — "valid" meaning the
// Cedar engine itself accepts it.
func TestCompileProducesValidCedar(t *testing.T) {
	p := DefaultPolicy(testManifest(t))
	text, err := p.Compile()
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if strings.TrimSpace(text) == "" {
		t.Fatal("Compile produced empty policy text")
	}
	if _, err := cedarengine.NewPolicySetFromBytes("test", []byte(text)); err != nil {
		t.Fatalf("compiled text is not valid Cedar: %v\n%s", err, text)
	}
	for _, want := range []string{`Role::"admin"`, `Role::"user"`, `Role::"auditor"`, `Action::"read"`} {
		if !strings.Contains(text, want) {
			t.Errorf("compiled policy is missing %q", want)
		}
	}
}

func TestCompileEmptyPolicy(t *testing.T) {
	text, err := (&Policy{}).Compile()
	if err != nil {
		t.Fatalf("compiling an empty policy should not error: %v", err)
	}
	if _, err := cedarengine.NewPolicySetFromBytes("test", []byte(text)); err != nil {
		t.Fatalf("empty-policy text is not valid Cedar: %v", err)
	}
}
