package keystore

import "context"

// Rotate re-wraps every DEK at fromVersion up to toVersion for tenantID,
// batchSize rows per committed batch, by driving store.RotateBatch until no
// rows remain. It is the resumable, batched KEK-rotation job (ADR 0002):
// because each batch commits its kek_version advance durably, progress
// survives a crash, and re-invoking Rotate resumes from where it stopped —
// it re-selects only the rows still at fromVersion. It returns the total rows
// rotated across every batch in this run.
//
// Rotation is bound by key-store write throughput, not compute, so the batch
// is the unit of durable progress; a batchSize below 1 is raised to 1 so the
// loop always makes progress rather than spinning.
func Rotate(ctx context.Context, store KeyStore, tenantID string, fromVersion, toVersion, batchSize int, rewrap Rewrap) (int, error) {
	if batchSize < 1 {
		batchSize = 1
	}
	total := 0
	for {
		n, err := store.RotateBatch(ctx, tenantID, fromVersion, toVersion, batchSize, rewrap)
		if err != nil {
			return total, err
		}
		total += n
		if n == 0 {
			return total, nil
		}
	}
}
