package storage

import (
	"context"
	"errors"
	"testing"
)

func TestCanonicalBucketsHaveDistinctCredentialDomains(t *testing.T) {
	backups := BackupsSpec()
	auditLog := AuditLogSpec()

	if backups.CredentialDomain == "" || auditLog.CredentialDomain == "" {
		t.Fatal("both canonical buckets must name a credential domain")
	}
	if backups.CredentialDomain == auditLog.CredentialDomain {
		t.Fatalf("backups and audit-log must not share a credential domain, both = %q", backups.CredentialDomain)
	}
}

func TestCanonicalBucketsCarryRetentionAsPolicy(t *testing.T) {
	backups := BackupsSpec()
	if backups.Retention.MinDays != 30 || backups.Retention.MaxDays != 35 {
		t.Fatalf("backups retention = %+v, want 30-35 days", backups.Retention)
	}

	auditLog := AuditLogSpec()
	if auditLog.Retention.MinDays != 365 || auditLog.Retention.MaxDays != 730 {
		t.Fatalf("audit-log retention = %+v, want 365-730 days", auditLog.Retention)
	}
}

func TestFakeExposesItsSpecAndRole(t *testing.T) {
	spec := AuditLogSpec()
	s := NewFake(spec, AppendOnly)

	if s.Spec().CredentialDomain != spec.CredentialDomain {
		t.Errorf("Spec().CredentialDomain = %q, want %q", s.Spec().CredentialDomain, spec.CredentialDomain)
	}
	if s.Role() != AppendOnly {
		t.Errorf("Role() = %v, want AppendOnly", s.Role())
	}
}

func TestReadWriteRolePutsGetsListsAndDeletes(t *testing.T) {
	ctx := context.Background()
	s := NewFake(BackupsSpec(), ReadWrite)

	if err := s.Put(ctx, "dump-1", []byte("alpha")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(ctx, "dump-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "alpha" {
		t.Errorf("Get = %q, want %q", got, "alpha")
	}

	// ReadWrite may overwrite.
	if err := s.Put(ctx, "dump-1", []byte("beta")); err != nil {
		t.Fatalf("Put overwrite: %v", err)
	}
	got, _ = s.Get(ctx, "dump-1")
	if string(got) != "beta" {
		t.Errorf("Get after overwrite = %q, want %q", got, "beta")
	}

	keys, err := s.List(ctx, "dump-")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 1 || keys[0] != "dump-1" {
		t.Errorf("List = %v, want [dump-1]", keys)
	}

	// ReadWrite may delete.
	if err := s.Delete(ctx, "dump-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(ctx, "dump-1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get after delete err = %v, want ErrNotFound", err)
	}
}

func TestAppendOnlyRoleAcceptsNewObjects(t *testing.T) {
	ctx := context.Background()
	s := NewFake(AuditLogSpec(), AppendOnly)

	if err := s.Put(ctx, "event-1", []byte("logged")); err != nil {
		t.Fatalf("Put new object under AppendOnly: %v", err)
	}
	got, err := s.Get(ctx, "event-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "logged" {
		t.Errorf("Get = %q, want %q", got, "logged")
	}
}

func TestAppendOnlyRoleRejectsOverwrite(t *testing.T) {
	ctx := context.Background()
	s := NewFake(AuditLogSpec(), AppendOnly)

	if err := s.Put(ctx, "event-1", []byte("logged")); err != nil {
		t.Fatalf("Put new object: %v", err)
	}
	err := s.Put(ctx, "event-1", []byte("tampered"))
	if !errors.Is(err, ErrOverwriteDenied) {
		t.Fatalf("Put overwrite under AppendOnly err = %v, want ErrOverwriteDenied", err)
	}
	// The original object is untouched.
	got, _ := s.Get(ctx, "event-1")
	if string(got) != "logged" {
		t.Errorf("object after rejected overwrite = %q, want %q", got, "logged")
	}
}

func TestAppendOnlyRoleRejectsDelete(t *testing.T) {
	ctx := context.Background()
	s := NewFake(AuditLogSpec(), AppendOnly)

	if err := s.Put(ctx, "event-1", []byte("logged")); err != nil {
		t.Fatalf("Put new object: %v", err)
	}
	err := s.Delete(ctx, "event-1")
	if !errors.Is(err, ErrDeleteDenied) {
		t.Fatalf("Delete under AppendOnly err = %v, want ErrDeleteDenied", err)
	}
	// The object survives the rejected delete.
	if _, err := s.Get(ctx, "event-1"); err != nil {
		t.Errorf("Get after rejected delete: %v", err)
	}
}

func TestGetMissingObjectReturnsErrNotFound(t *testing.T) {
	ctx := context.Background()
	s := NewFake(BackupsSpec(), ReadWrite)

	if _, err := s.Get(ctx, "absent"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get missing err = %v, want ErrNotFound", err)
	}
}

func TestDeleteMissingObjectUnderReadWriteReturnsErrNotFound(t *testing.T) {
	ctx := context.Background()
	s := NewFake(BackupsSpec(), ReadWrite)

	if err := s.Delete(ctx, "absent"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Delete missing err = %v, want ErrNotFound", err)
	}
}

// The Fake satisfies the Store interface — both roles are the same type,
// so a caller wires append-only and read-write stores identically.
var _ Store = (*Fake)(nil)
