---
title: PII detection
weight: 6
---

Kura assumes free-text fields contain PII. A **PII detection layer** scans that text,
tags the spans it finds with a [category](../schema-manifest/#pii-categories), and
those categories drive [Cedar's category-based masking](../policy/).

## The detector: OpenAI Privacy Filter, self-hosted

The detection model is the **OpenAI Privacy Filter** — an Apache-2.0, open-weight
token-classification model (1.5B parameters) that detects eight PII categories. It
runs **self-hosted**: a separate, internal-only service, never exposed publicly.
Self-hosting is the point — no client text leaves the deployment for detection, so no
new sub-processor enters the data chain.

Kura's `Category` enum mirrors the model's eight detection categories, so a detected
span and a manifest tag speak the same vocabulary with no translation.

## The client interface

The core never talks to the model directly. It depends on a narrow `Detector`
interface — `Detect(text) → []Span` — with two implementations:

- **`ServiceDetector`** — the real client: an HTTP client for the self-hosted service.
- **`FakeDetector`** — an in-memory implementation for unit tests, so the core's tests
  never require the live service.
- **`PatternDetector`** — a regex-based implementation for development and offline use:
  it detects emails, phone numbers, and US SSNs (as the high-sensitivity
  `account_number` category). It is **not** the real model — it exists so a local Kura
  can scan, classify, and mask without standing up the Privacy Filter service. `kura dev
  pii-detector` serves it over the same JSON contract below; see the
  [local dev instance](../getting-started/local-development).

A `Span` is the structured metadata for one detected occurrence: **category, offset,
length, and confidence**.

### Service contract

The self-hosted service wraps the model behind this JSON contract; `ServiceDetector`
speaks it, and a span carrying a category Kura does not recognize fails loudly rather
than passing through.

```
POST <endpoint>
Request:  { "text": "..." }
Response: { "spans": [ { "category": "private_email", "offset": 0, "length": 17, "confidence": 0.98 } ] }
```

Offsets and lengths are byte positions into the request text.

## The two call sites

`Scanner` runs the detector at both points the reference architecture requires:

- **Ingestion** — `ScanRecord` scans every free-text field of a record and returns
  the detected spans per field, to be stored as structured metadata alongside the
  source text.
- **Access time** — `DetectCategories` re-scans a field's text and returns the
  distinct categories present. Re-scanning at access time catches *drift*: if the
  model improves between when data was ingested and when it is read, the masking
  decision uses the better result. Its output feeds straight into Cedar's
  category-based masking.
