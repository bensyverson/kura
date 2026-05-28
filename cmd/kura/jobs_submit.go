package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/bensyverson/kura/internal/clio"
	"github.com/bensyverson/kura/internal/jobs"
	"github.com/spf13/cobra"
)

// submitJob POSTs a job to /api/jobs and returns the created (or
// retry-attached) job. It is the shared submit path for the long-running
// verbs (backup, restore): each is a thin presenter over the async
// ledger. The caller's identity is the cached bearer token — the server
// stamps the authenticated principal into the params, so the CLI never
// sends an actor itself.
func submitJob(cmd *cobra.Command, verb, server, kind, idempotencyKey string, params any) (jobs.Job, error) {
	cache, err := defaultTokenCache()
	if err != nil {
		return jobs.Job{}, err
	}
	_, token, err := cache.load()
	if err != nil {
		return jobs.Job{}, err
	}

	var rawParams json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return jobs.Job{}, clio.InternalError(verb, "encoding params: %w", err)
		}
		rawParams = b
	}
	body, err := json.Marshal(struct {
		Kind           string          `json:"kind"`
		IdempotencyKey string          `json:"idempotency_key"`
		Params         json.RawMessage `json:"params,omitempty"`
	}{Kind: kind, IdempotencyKey: idempotencyKey, Params: rawParams})
	if err != nil {
		return jobs.Job{}, clio.InternalError(verb, "encoding request: %w", err)
	}

	target := strings.TrimRight(server, "/") + "/api/jobs"
	req, err := http.NewRequestWithContext(cmd.Context(), http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return jobs.Job{}, clio.InternalError(verb, "building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return jobs.Job{}, clio.TransientError(verb, "%w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return jobs.Job{}, classifyHTTPStatus(verb, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var out struct {
		Job     jobs.Job `json:"job"`
		Created bool     `json:"created"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return jobs.Job{}, clio.InternalError(verb, "decoding server response: %w", err)
	}
	return out.Job, nil
}

// newIdempotencyKey returns a fresh random key. A backup is not naturally
// idempotent on any natural attribute, so each invocation gets a unique
// key by default; the caller may override it (e.g. to re-attach to an
// in-flight job) via --idempotency-key.
func newIdempotencyKey() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
