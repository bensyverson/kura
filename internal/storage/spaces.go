package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// SpacesConfig is the per-deployment wiring for a DO Spaces bucket. The
// logical BucketSpec (BackupsSpec/AuditLogSpec) names the role and
// retention policy; SpacesConfig supplies the concrete endpoint,
// credentials, and bucket name the IaC phase provisions for this
// deployment.
type SpacesConfig struct {
	// Endpoint is the S3 host, without scheme — e.g.
	// "nyc3.digitaloceanspaces.com" for DO Spaces, or "localhost:59000"
	// for a local MinIO.
	Endpoint string
	// Region is the Spaces region slug — e.g. "nyc3". S3-compatible
	// stores require a region for request signing.
	Region string
	// AccessKey and SecretKey are the credentials for this bucket's
	// credential domain. Append-only and read-write callers pass
	// different keys for the same bucket.
	AccessKey string
	SecretKey string
	// Bucket is the concrete, per-deployment bucket name the IaC mapped
	// the logical BucketSpec.Name to.
	Bucket string
	// UseSSL selects HTTPS. Real DO Spaces is always TLS; a local MinIO
	// over plain HTTP sets this false.
	UseSSL bool
}

// Spaces is the production Store backed by a DigitalOcean Spaces bucket
// (or any S3-compatible endpoint). It enforces the same role contract as
// the Fake in Go — under AppendOnly, Put of an existing key and any
// Delete are refused — so callers behave identically against Spaces and
// the Fake. That Go-level enforcement is the belt; the deny-delete bucket
// policy administered from a separate credential domain (see the IaC
// phase) is the suspenders.
type Spaces struct {
	spec   BucketSpec
	role   Role
	bucket string
	client *minio.Client
}

// NewSpaces opens a Store for spec against the bucket described by cfg,
// with the given role. It does not create the bucket: bucket creation,
// versioning, and the deny-delete policy are IaC concerns owned by a
// separate administrative credential domain.
func NewSpaces(spec BucketSpec, role Role, cfg SpacesConfig) (*Spaces, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("storage: Spaces endpoint is required")
	}
	if cfg.Bucket == "" {
		return nil, errors.New("storage: Spaces bucket is required")
	}
	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseSSL,
		Region: cfg.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("storage: opening Spaces client: %w", err)
	}
	return &Spaces{
		spec:   spec,
		role:   role,
		bucket: cfg.Bucket,
		client: client,
	}, nil
}

// Spec returns the bucket's immutable description.
func (s *Spaces) Spec() BucketSpec { return s.spec }

// Role returns the access level this Store was opened with.
func (s *Spaces) Role() Role { return s.role }

// Put writes data at key. Under AppendOnly, putting an existing key
// returns ErrOverwriteDenied and leaves the stored object untouched.
func (s *Spaces) Put(ctx context.Context, key string, data []byte) error {
	if s.role == AppendOnly {
		exists, err := s.exists(ctx, key)
		if err != nil {
			return err
		}
		if exists {
			return ErrOverwriteDenied
		}
	}
	_, err := s.client.PutObject(ctx, s.bucket, key, bytes.NewReader(data), int64(len(data)), minio.PutObjectOptions{})
	if err != nil {
		return fmt.Errorf("storage: put %q: %w", key, err)
	}
	return nil
}

// Get returns the object at key, or ErrNotFound.
func (s *Spaces) Get(ctx context.Context, key string) ([]byte, error) {
	obj, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("storage: get %q: %w", key, err)
	}
	defer obj.Close()
	// minio defers the request until the first read, so a missing key
	// surfaces here rather than at GetObject.
	data, err := io.ReadAll(obj)
	if err != nil {
		if isNoSuchKey(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("storage: get %q: %w", key, err)
	}
	return data, nil
}

// List returns the keys with the given prefix, in lexical order.
func (s *Spaces) List(ctx context.Context, prefix string) ([]string, error) {
	var keys []string
	for obj := range s.client.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true}) {
		if obj.Err != nil {
			return nil, fmt.Errorf("storage: list %q: %w", prefix, obj.Err)
		}
		keys = append(keys, obj.Key)
	}
	// S3 already returns keys in lexical order, but sorting makes the
	// contract explicit and independent of the endpoint's guarantees.
	sort.Strings(keys)
	return keys, nil
}

// Delete removes the object at key. Under AppendOnly it returns
// ErrDeleteDenied and leaves the object in place; under ReadWrite an
// absent key returns ErrNotFound.
func (s *Spaces) Delete(ctx context.Context, key string) error {
	if s.role == AppendOnly {
		return ErrDeleteDenied
	}
	// S3 DeleteObject is idempotent — it succeeds for an absent key — so
	// the ErrNotFound contract requires an explicit existence check.
	exists, err := s.exists(ctx, key)
	if err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}
	if err := s.client.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{}); err != nil {
		return fmt.Errorf("storage: delete %q: %w", key, err)
	}
	return nil
}

// exists reports whether key is present in the bucket, mapping a missing
// object to (false, nil) rather than an error.
func (s *Spaces) exists(ctx context.Context, key string) (bool, error) {
	_, err := s.client.StatObject(ctx, s.bucket, key, minio.StatObjectOptions{})
	if err != nil {
		if isNoSuchKey(err) {
			return false, nil
		}
		return false, fmt.Errorf("storage: stat %q: %w", key, err)
	}
	return true, nil
}

// isNoSuchKey reports whether err is an S3 "object not found" response.
func isNoSuchKey(err error) bool {
	resp := minio.ToErrorResponse(err)
	return resp.Code == "NoSuchKey" || resp.StatusCode == http.StatusNotFound
}
