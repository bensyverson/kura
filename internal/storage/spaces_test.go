package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// bucketCounter makes each test's bucket name unique without relying on
// time or randomness, so parallel runs never collide.
var bucketCounter atomic.Int64

// spacesTestConfig reads the KURA_TEST_SPACES_* variables, skipping the
// test when they are unset — the same gate as every other integration
// test, so `go test ./...` stays green without a running MinIO.
//
// Bring the endpoint up with:  eval "$(scripts/test-spaces.sh)"
func spacesTestConfig(t *testing.T) SpacesConfig {
	t.Helper()
	endpoint := os.Getenv("KURA_TEST_SPACES_ENDPOINT")
	if endpoint == "" {
		t.Skip("KURA_TEST_SPACES_ENDPOINT not set; skipping object-storage integration test")
	}
	return SpacesConfig{
		Endpoint:  endpoint,
		Region:    os.Getenv("KURA_TEST_SPACES_REGION"),
		AccessKey: os.Getenv("KURA_TEST_SPACES_ACCESS_KEY"),
		SecretKey: os.Getenv("KURA_TEST_SPACES_SECRET_KEY"),
		// MinIO is served over plain HTTP locally; real DO Spaces is TLS.
		UseSSL: false,
	}
}

// newTestSpaces provisions a fresh, empty bucket on the test endpoint and
// returns a Spaces opened against it with role. Bucket creation is an IaC
// concern in production, so the runtime client never creates buckets —
// the test harness does. The bucket and its contents are removed on
// cleanup.
func newTestSpaces(t *testing.T, role Role) *Spaces {
	t.Helper()
	cfg := spacesTestConfig(t)

	bucket := testBucketName(t)
	admin, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseSSL,
		Region: cfg.Region,
	})
	if err != nil {
		t.Fatalf("test minio client: %v", err)
	}
	ctx := context.Background()
	if err := admin.MakeBucket(ctx, bucket, minio.MakeBucketOptions{Region: cfg.Region}); err != nil {
		t.Fatalf("creating test bucket %q: %v", bucket, err)
	}
	t.Cleanup(func() {
		objects := admin.ListObjects(context.Background(), bucket, minio.ListObjectsOptions{Recursive: true})
		for obj := range objects {
			_ = admin.RemoveObject(context.Background(), bucket, obj.Key, minio.RemoveObjectOptions{})
		}
		_ = admin.RemoveBucket(context.Background(), bucket)
	})

	cfg.Bucket = bucket
	s, err := NewSpaces(AuditLogSpec(), role, cfg)
	if err != nil {
		t.Fatalf("NewSpaces: %v", err)
	}
	return s
}

// testBucketName derives an S3-legal bucket name (lowercase, 3-63 chars,
// no underscores) from the test name plus a unique counter.
func testBucketName(t *testing.T) string {
	t.Helper()
	n := bucketCounter.Add(1)
	clean := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		default:
			return '-'
		}
	}, t.Name())
	name := fmt.Sprintf("kura-test-%s-%d", clean, n)
	if len(name) > 63 {
		name = name[:63]
	}
	return name
}

func TestSpacesExposesItsSpecAndRole(t *testing.T) {
	cfg := spacesTestConfig(t)
	cfg.Bucket = "unused"
	s, err := NewSpaces(BackupsSpec(), AppendOnly, cfg)
	if err != nil {
		t.Fatalf("NewSpaces: %v", err)
	}
	if s.Spec().CredentialDomain != BackupsSpec().CredentialDomain {
		t.Errorf("Spec().CredentialDomain = %q, want %q", s.Spec().CredentialDomain, BackupsSpec().CredentialDomain)
	}
	if s.Role() != AppendOnly {
		t.Errorf("Role() = %v, want AppendOnly", s.Role())
	}
}

func TestSpacesReadWriteRolePutsGetsListsAndDeletes(t *testing.T) {
	ctx := context.Background()
	s := newTestSpaces(t, ReadWrite)

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

func TestSpacesAppendOnlyRoleAcceptsNewObjects(t *testing.T) {
	ctx := context.Background()
	s := newTestSpaces(t, AppendOnly)

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

func TestSpacesAppendOnlyRoleRejectsOverwrite(t *testing.T) {
	ctx := context.Background()
	s := newTestSpaces(t, AppendOnly)

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

func TestSpacesAppendOnlyRoleRejectsDelete(t *testing.T) {
	ctx := context.Background()
	s := newTestSpaces(t, AppendOnly)

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

func TestSpacesGetMissingObjectReturnsErrNotFound(t *testing.T) {
	ctx := context.Background()
	s := newTestSpaces(t, ReadWrite)

	if _, err := s.Get(ctx, "absent"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get missing err = %v, want ErrNotFound", err)
	}
}

func TestSpacesDeleteMissingObjectUnderReadWriteReturnsErrNotFound(t *testing.T) {
	ctx := context.Background()
	s := newTestSpaces(t, ReadWrite)

	if err := s.Delete(ctx, "absent"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Delete missing err = %v, want ErrNotFound", err)
	}
}

func TestSpacesListReturnsKeysInLexicalOrder(t *testing.T) {
	ctx := context.Background()
	s := newTestSpaces(t, ReadWrite)

	// Insert out of order; List must return them sorted.
	for _, k := range []string{"seg-3", "seg-1", "seg-2"} {
		if err := s.Put(ctx, k, []byte("x")); err != nil {
			t.Fatalf("Put %q: %v", k, err)
		}
	}
	// A key outside the prefix must be excluded.
	if err := s.Put(ctx, "other", []byte("x")); err != nil {
		t.Fatalf("Put other: %v", err)
	}

	keys, err := s.List(ctx, "seg-")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []string{"seg-1", "seg-2", "seg-3"}
	if len(keys) != len(want) {
		t.Fatalf("List = %v, want %v", keys, want)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Errorf("List[%d] = %q, want %q (full: %v)", i, keys[i], want[i], keys)
		}
	}
}

// Spaces satisfies the Store interface — the same concrete type serves
// both roles, exactly as the Fake does.
var _ Store = (*Spaces)(nil)
