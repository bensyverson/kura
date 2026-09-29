#!/usr/bin/env python3
"""DEK key-store sizing analysis for Kura field-level encryption.

Validates whether per-field-value DEKs (decision D4) are operationally
viable at a target volume, by modelling the erasable key store as a
dedicated Postgres instance holding one KEK-wrapped DEK per encrypted
field-value.

The key-store row mirrors kura.record_field_values' identity:
    (record_id uuid, field_name text, tenant_id uuid, wrapped_dek bytea,
     kek_version int)
keyed by the same (record_id, field_name) primary key.

This is an analysis tool, not a benchmark: it estimates storage, KEK
rotation cost, and per-read unwrap overhead from first principles so the
breakpoints are explicit. Re-run with different volumes/wrap schemes to
explore the envelope.

Usage:
    python3 scripts/dek_sizing.py
    python3 scripts/dek_sizing.py --volumes 10e6 50e6 100e6 500e6
"""

import argparse

# --- Per-DEK row-size model (bytes), Postgres heap + PK btree index ---
#
# Heap tuple:
#   23  tuple header
#    1  null bitmap / alignment slack
#   16  record_id   (uuid)
#   16  tenant_id   (uuid)
#   ~16 field_name  (text: ~12 chars + varlena header)
#    4  kek_version (int)
#  wrapped_dek (bytea + varlena header): low = AES-KW (RFC 3394) of a
#  256-bit DEK = 40 B + 4; high = AES-256-GCM = 12 nonce + 32 ct + 16
#  tag = 60 B + 4.
#
# PK btree on (record_id, field_name): ~16 + 16 key + ~16 line-pointer/
# header overhead per entry.
#
# We add a bloat/fillfactor multiplier to reach a realistic on-disk figure.

HEAP_FIXED = 23 + 1 + 16 + 16 + 16 + 4          # everything but wrapped_dek
WRAP_LOW = 40 + 4                                # AES-KW
WRAP_HIGH = 60 + 4                               # AES-256-GCM
PK_INDEX = 16 + 16 + 16                          # btree entry
BLOAT = 1.35                                     # fillfactor + page/index slack

# --- Perf model ---
UNWRAP_US = 2.0          # AES unwrap CPU cost per DEK (microseconds)
ROTATE_WRITES_PER_S = 20_000  # sustained UPDATE throughput, online batched


def row_bytes(wrap):
    return (HEAP_FIXED + wrap + PK_INDEX) * BLOAT


def human(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:,.1f} {unit}"
        n /= 1024
    return f"{n:,.1f} PB"


def hms(seconds):
    if seconds < 90:
        return f"{seconds:,.0f} s"
    if seconds < 5400:
        return f"{seconds / 60:,.1f} min"
    return f"{seconds / 3600:,.1f} h"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--volumes", nargs="+", type=float,
                    default=[1e6, 10e6, 50e6, 100e6, 500e6],
                    help="DEK counts to model (one per encrypted field-value)")
    args = ap.parse_args()

    lo = row_bytes(WRAP_LOW)
    hi = row_bytes(WRAP_HIGH)
    print(f"Per-DEK row (heap+PK index, x{BLOAT} bloat): "
          f"{lo:,.0f}-{hi:,.0f} bytes\n")

    hdr = f"{'DEKs':>14} | {'store size (AES-KW..GCM)':>28} | {'KEK re-wrap':>12}"
    print(hdr)
    print("-" * len(hdr))
    for v in args.volumes:
        size_lo = v * lo
        size_hi = v * hi
        rotate = v / ROTATE_WRITES_PER_S
        size_col = f"{human(size_lo)} .. {human(size_hi)}"
        print(f"{v:>14,.0f} | {size_col:>28} | {hms(rotate):>12}")

    print()
    print("Per-read unwrap (cold, no cache): "
          f"~{UNWRAP_US:.0f} us CPU + 1 indexed point-lookup to the key store.")
    print("With an in-process LRU DEK cache, hot reads are a map hit (no unwrap, "
          "no round-trip).")
    print(f"KEK rotation re-wraps every DEK in place (DEK value unchanged, so "
          f"live & immutable-backup ciphertext stay decryptable); cost is bound "
          f"by key-store write throughput (~{ROTATE_WRITES_PER_S:,}/s, online).")


if __name__ == "__main__":
    main()
