package cedar

import (
	"testing"

	"github.com/bensyverson/kura/internal/manifest"
	"github.com/bensyverson/kura/internal/pii"
)

func testManifest(t *testing.T) *manifest.Manifest {
	t.Helper()
	m, err := manifest.ParseFile("../manifest/testdata/valid.json")
	if err != nil {
		t.Fatalf("load test manifest: %v", err)
	}
	return m
}

func TestActionValid(t *testing.T) {
	for _, a := range AllActions() {
		if !a.Valid() {
			t.Errorf("%q should be a valid action", a)
		}
	}
	for _, a := range []Action{"", "READ", "purge"} {
		if a.Valid() {
			t.Errorf("%q should not be a valid action", a)
		}
	}
}

// N2d: the default three-role model is expressible in the IR.
func TestDefaultPolicyHasThreeRoles(t *testing.T) {
	p := DefaultPolicy(testManifest(t))
	want := map[string]bool{"admin": false, "user": false, "auditor": false}
	for _, r := range p.Roles {
		if _, ok := want[r.Name]; !ok {
			t.Errorf("unexpected role %q", r.Name)
		}
		want[r.Name] = true
	}
	for name, found := range want {
		if !found {
			t.Errorf("default policy is missing the %q role", name)
		}
	}
}

// ScS: the IR's axes (roles x entities x PII-categories x actions) come
// from the manifest, and the IR validates against it.
func TestDefaultPolicyValidatesAgainstManifest(t *testing.T) {
	m := testManifest(t)
	p := DefaultPolicy(m)
	if err := p.ValidateAgainst(m); err != nil {
		t.Fatalf("default policy should validate against its own manifest: %v", err)
	}
	for _, g := range p.Grants {
		if _, ok := m.Entity(g.Entity); !ok {
			t.Errorf("grant references entity %q absent from the manifest", g.Entity)
		}
	}
	for _, e := range m.Entities {
		covered := false
		for _, g := range p.Grants {
			if g.Entity == e.Name {
				covered = true
				break
			}
		}
		if !covered {
			t.Errorf("default policy does not cover manifest entity %q", e.Name)
		}
	}
}

func TestPolicyValidationCatchesBadReferences(t *testing.T) {
	m := testManifest(t)

	good := &Policy{
		Roles:  []Role{{Name: "user"}},
		Grants: []Grant{{Role: "user", Entity: "customer", Action: ActionRead}},
	}
	if err := good.ValidateAgainst(m); err != nil {
		t.Fatalf("base policy should be valid: %v", err)
	}

	bad := map[string]*Policy{
		"unknown role": {
			Roles:  []Role{{Name: "user"}},
			Grants: []Grant{{Role: "ghost", Entity: "customer", Action: ActionRead}},
		},
		"unknown entity": {
			Roles:  []Role{{Name: "user"}},
			Grants: []Grant{{Role: "user", Entity: "ghost", Action: ActionRead}},
		},
		"invalid action": {
			Roles:  []Role{{Name: "user"}},
			Grants: []Grant{{Role: "user", Entity: "customer", Action: "purge"}},
		},
		"invalid pii category": {
			Roles:  []Role{{Name: "user"}},
			Grants: []Grant{{Role: "user", Entity: "customer", Action: ActionRead, VisiblePII: []pii.Category{"ssn"}}},
		},
		"visible pii on a write action": {
			Roles:  []Role{{Name: "user"}},
			Grants: []Grant{{Role: "user", Entity: "customer", Action: ActionUpdate, VisiblePII: []pii.Category{pii.CategoryEmail}}},
		},
		"duplicate role": {
			Roles:  []Role{{Name: "user"}, {Name: "user"}},
			Grants: nil,
		},
		"empty role name": {
			Roles:  []Role{{Name: ""}},
			Grants: nil,
		},
	}
	for name, p := range bad {
		if err := p.ValidateAgainst(m); err == nil {
			t.Errorf("%s: expected a validation error, got nil", name)
		}
	}
}

func TestDefaultRoleSemantics(t *testing.T) {
	m := testManifest(t)
	p := DefaultPolicy(m)

	visible := func(role, entity string) []pii.Category {
		for _, g := range p.Grants {
			if g.Role == role && g.Entity == entity && g.Action == ActionRead {
				return g.VisiblePII
			}
		}
		return nil
	}
	can := func(role, entity string, a Action) bool {
		for _, g := range p.Grants {
			if g.Role == role && g.Entity == entity && g.Action == a {
				return true
			}
		}
		return false
	}

	if got := len(visible("admin", "customer")); got != len(pii.Categories()) {
		t.Errorf("admin should see all %d PII categories, sees %d", len(pii.Categories()), got)
	}
	for _, c := range visible("user", "customer") {
		if c.HighSensitivity() {
			t.Errorf("user should not see high-sensitivity category %q", c)
		}
	}
	if len(visible("user", "customer")) == 0 {
		t.Error("user should see the non-high-sensitivity categories")
	}
	if len(visible("auditor", "customer")) != 0 {
		t.Error("auditor should see no PII categories")
	}
	if can("auditor", "customer", ActionCreate) || can("auditor", "customer", ActionDelete) {
		t.Error("auditor should be read-only")
	}
	if !can("auditor", "customer", ActionRead) || !can("auditor", "customer", ActionList) {
		t.Error("auditor should be able to read and list")
	}
}
