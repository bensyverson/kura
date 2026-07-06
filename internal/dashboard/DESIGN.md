---
version: alpha
name: Kura — Storehouse
description: >
  The local Kura admin dashboard. A calm, precise instrument for the
  1–3 people per client who audit access to PII. Light theme is warm
  plaster; dark theme is sumi ink. Indigo is the single accent; vermilion
  is reserved strictly for things that need attention. System fonts only,
  zero dependencies, server-side rendered. Token values below are the
  LIGHT (plaster) theme; the dark (sumi) equivalents are listed in the
  Colors section and shipped via prefers-color-scheme.
colors:
  primary: "#294a72"          # 藍 indigo — interaction, links, active nav, focus
  primary-weak: "#e2e6ee"     # indigo tint for quiet fills
  secondary: "#6a6253"        # muted slate — metadata, labels, captions
  tertiary: "#a8412a"         # 朱 vermilion — attention/alert ONLY
  tertiary-weak: "#f3e1da"
  neutral: "#e7e0d2"          # plaster — page background
  surface: "#faf6ee"          # panels, top bar
  surface-2: "#f0e9da"        # insets, command blocks, hover fills
  on-surface: "#211f19"       # primary text (sumi on plaster)
  on-surface-muted: "#6a6253"
  border: "#d6ccb8"           # hairline
  border-strong: "#c2b69d"
  badge-admin-bg: "#f1ddd3"
  badge-admin-fg: "#8c3a22"
  badge-consultant-bg: "#dde3ee"
  badge-consultant-fg: "#294a72"
  badge-user-bg: "#dde8da"
  badge-user-fg: "#3c5a36"
  badge-service-bg: "#e5dfec"
  badge-service-fg: "#574171"
typography:
  headline-lg:                # page title (h1)
    fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif"
    fontSize: 1.5rem
    fontWeight: 680
    lineHeight: 1.2
    letterSpacing: -0.015em
  body-lg:                    # lede paragraph
    fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif"
    fontSize: 1.04rem
    fontWeight: 400
    lineHeight: 1.55
  body-md:                    # default body
    fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif"
    fontSize: 0.97rem
    fontWeight: 400
    lineHeight: 1.55
  label-eyebrow:             # section kicker above a title
    fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif"
    fontSize: 0.72rem
    fontWeight: 700
    lineHeight: 1
    letterSpacing: 0.14em
  label-field:               # definition-list term, table header
    fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif"
    fontSize: 0.74rem
    fontWeight: 600
    lineHeight: 1.3
    letterSpacing: 0.08em
  mono:                      # IDs, tokens, command blocks, raw values
    fontFamily: "ui-monospace, SFMono-Regular, SF Mono, Menlo, Consolas, Liberation Mono, monospace"
    fontSize: 0.88rem
    fontWeight: 400
    lineHeight: 1.5
rounded:
  sm: 0.25rem
  md: 0.4rem
  full: 999px
spacing:
  "1": 0.25rem
  "2": 0.5rem
  "3": 0.75rem
  "4": 1rem
  "5": 1.5rem
  "6": 2rem
  "8": 3rem
  content-max: 66rem
components:
  topbar:
    backgroundColor: "{colors.surface}"
  nav-link:
    textColor: "{colors.secondary}"
    rounded: "{rounded.sm}"
    padding: 0.5rem
  nav-link-active:
    textColor: "{colors.primary}"
  panel:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.md}"
    padding: 2rem
  eyebrow:
    textColor: "{colors.secondary}"
    typography: "{typography.label-eyebrow}"
  badge-admin:
    backgroundColor: "{colors.badge-admin-bg}"
    textColor: "{colors.badge-admin-fg}"
    rounded: "{rounded.sm}"
  badge-consultant:
    backgroundColor: "{colors.badge-consultant-bg}"
    textColor: "{colors.badge-consultant-fg}"
    rounded: "{rounded.sm}"
  badge-user:
    backgroundColor: "{colors.badge-user-bg}"
    textColor: "{colors.badge-user-fg}"
    rounded: "{rounded.sm}"
  badge-service:
    backgroundColor: "{colors.badge-service-bg}"
    textColor: "{colors.badge-service-fg}"
    rounded: "{rounded.sm}"
  command-block:
    backgroundColor: "{colors.surface-2}"
    typography: "{typography.mono}"
    rounded: "{rounded.sm}"
    padding: 0.75rem
---

# Kura Dashboard — Design System

This is the normative design system for the **local Kura dashboard**
(`internal/dashboard`). The dashboard is a loopback-bound web app the
client's 1–3 admins run on their own machine; it renders audit logs,
user roles, and a masked PII data browser. The Overview page exists; the
Users & roles, Access review, Data browser, Audit log, Cedar policy
viewer, and Programmatic-access pages are built later by separate tasks
and **must** follow this document so they stay coherent.

Implementation lives in `static/app.css` (the tokens here mirror its
custom properties exactly) and `templates/*.html`. The frontmatter tokens
are normative; the prose explains how to apply them.

## Overview

The product is a vault. The name *kura* (蔵) is the traditional Japanese
fireproof storehouse — thick plaster walls, dark timber, a calm and
permanent place for what matters. The UI should feel **trustworthy,
precise, and quiet**: an instrument for careful work, not a marketing
surface. Density is moderate and legible; whitespace is generous but not
airy; nothing animates for its own sake.

The audience is technical and accountable — they are reviewing who can
see personal data. Earn their trust with restraint: hairline rules,
exact alignment, tabular figures, and a single accent used sparingly.
When in doubt, remove ornament.

Two themes ship, selected by `prefers-color-scheme`: **plaster** (light)
and **sumi** (dark). Both must be designed; neither is an afterthought.

## Colors

The palette is high-contrast warm neutrals with one structural accent and
one alert color. Never introduce a new hue without adding it here first.

- **Primary — Indigo 藍 (`#294a72`):** the sole interaction color. Links,
  the active-nav underline, focus rings, the panel "vault seam," and the
  brand mark. In dark theme it lightens to `#8eaed6`.
- **Secondary — Slate (`#6a6253`):** muted text — metadata, eyebrows,
  field labels, captions. Dark: `#a59a85`.
- **Tertiary — Vermilion 朱 (`#a8412a`):** **attention only.** Overdue
  access reviews, IdP mismatches, audit anomalies, destructive-action
  confirmation. Never decorative, never an accent for ordinary UI. Dark:
  `#e08163`.
- **Neutral — Plaster (`#e7e0d2`):** the page background. Dark — sumi:
  `#16150f`.
- **Surface (`#faf6ee`):** panels and the top bar sit above the plaster.
  Dark: `#201e17`. **Surface-2 (`#f0e9da`):** insets, command blocks, and
  hover fills. Dark: `#29261d`.
- **On-surface (`#211f19`):** primary text, warm near-black sumi. Dark:
  `#ece5d5`.
- **Borders:** hairline `#d6ccb8` / strong `#c2b69d`. Dark: `#38342a` /
  `#4a4537`.

Principal-type **badges** use muted traditional pigments so a role reads
at a glance without shouting: admin = vermilion family, consultant =
indigo, user = young-leaf green (萌黄), service = murasaki (紫). Each has a
light and dark pair in the tokens.

## Typography

System fonts only — by hard constraint, no web fonts. Character comes
from **weight, tracking, and tabular figures**, not a typeface.

- **Headline (`headline-lg`):** page titles. Semi-bold (680), tight
  tracking. One `<h1>` per page.
- **Body (`body-md`, `body-lg`):** regular weight, 1.55 line-height. The
  `body-lg` lede introduces a page in one sentence.
- **Eyebrow (`label-eyebrow`):** a short uppercase kicker above the title
  (e.g. `DASHBOARD`, `AUTHENTICATION`), 0.14em tracking. This is the
  signature typographic move — use it once per panel, never as a body
  style.
- **Field labels (`label-field`):** definition-list terms and table
  headers — uppercase, 0.08em tracking, muted.
- **Mono (`mono`):** all machine values — IDs, tokens, timestamps, raw
  field values in the data browser, command blocks. Pair with
  `font-variant-numeric: tabular-nums` wherever numbers align in columns.

Use at most two weights on a screen (regular + the 680 headline). Set
counts, IDs, and any aligned numerals with tabular figures.

## Layout

A single centered column, **max-width `content-max` (66rem)**, with
generous page padding (`spacing.8` top, `spacing.5` sides). The top bar
is full-bleed; content is contained.

Spacing follows the modular scale in the tokens (a 0.25rem base). Group
related material in **panels** with `spacing.6` internal padding. Logical
pages are real routes (`/users`, `/audit`, `/data/{entity}`); query
strings are reserved for search, sort, and pagination *within* a page —
never for page identity (no `?page=users`).

Responsive: below ~44rem the nav wraps to its own full-width row beneath
the brand and session, and the facts grid collapses to a single column.

## Elevation & Depth

Depth is **tonal, not heavy**. The page is plaster; panels are a lighter
surface above it; insets (command blocks) step back down to surface-2.
Shadows are a whisper (`0 4px 14px` at 6% on light, deeper on dark) —
enough to lift a panel off the wall, never a drop-shadow flourish.

Two structural accents replace heavy elevation:
- the top bar carries a 2px indigo sill (`inset 0 -2px 0` primary);
- each panel carries a 3px indigo **vault seam** down its left edge.

Use these instead of inventing new shadows.

## Shapes

Restrained, engineered softness. Corner radius is small and consistent:
`rounded.sm` (4px) for chips, buttons, inputs, command blocks; `rounded.md`
(≈6px) for panels; `rounded.full` only for pill toggles. Do not mix sharp
and round corners in one view. Borders are always hairline (1px).

## Components

- **Top bar:** brand (with the 蔵 mark) · primary nav · session identity
  (email + principal badge). The active nav link is indigo with a 2px
  indigo underline tab.
- **Panel:** the primary container — surface, hairline border, md radius,
  whisper shadow, indigo vault seam. Open with an eyebrow, then the h1.
- **Badge:** small, sm-radius, capitalized; principal-type variants use
  the pigment pairs above. Reuse this for any short status token.
- **Facts list:** a two-column `<dl>` (uppercase muted term, tabular
  value) bracketed by hairline rules — the canonical way to show a record
  or entity's key/value detail.
- **Command block:** monospace, surface-2, sm radius, left rule; wrap in
  the `<kura-copy>` custom element to add a copy button.
- **Tables (data browser, audit log):** hairline row dividers, uppercase
  `label-field` headers, mono + tabular values, zebra via surface-2 only
  if density demands it. Mask PII server-side; never render an unmasked
  value the API masked.
- **Erased fields (`badge-erased`, `.erased-value`):** a field whose
  encryption key was crypto-shredded renders with a **quiet neutral badge**
  (surface-2 / muted, like `badge-soon`) and the italic muted `[erased]`
  sentinel in place of a value — never the vermilion attention pigment,
  because erasure is a settled, permanent fact, not an action to take. This
  keeps three read states visually distinct: a **masked** value (the
  server's `[redacted]` text), an **erased** value (`[erased]` + badge), and
  a field that was **never set** (a muted em-dash). The `[erased]` sentinel
  matches the CLI so the two surfaces read the same.

### Progressive enhancement (non-negotiable)

Every page is fully rendered and usable **server-side**. JavaScript only
*enhances* existing markup — it never produces primary content. Custom
elements (`<kura-copy>`, future `<kura-sortable>`, etc.) wrap
server-rendered HTML and degrade to that HTML when scripting is off. No
client-side routing, no client-side data fetching, no framework.

## Do's and Don'ts

- **Do** use indigo (primary) as the only accent for ordinary interaction.
- **Do** reserve vermilion (tertiary) exclusively for things that need
  attention — overdue reviews, IdP mismatches, destructive confirmations.
- **Do** lead each panel with one uppercase eyebrow and one `<h1>`.
- **Do** set IDs, counts, and timestamps in mono with tabular figures.
- **Do** design both plaster and sumi themes for every new surface.
- **Do** treat the policy viewer's grid as the *complete* policy. The
  structured IR is the enforced ceiling (decided 2026-05-19 — Kura admits no
  free-form Cedar; see the Cedar policy concept doc), so the grid is the
  whole, authoritative picture, never a partial view above hidden rules.
- **Don't** add a new color, font, or radius without first adding it here.
- **Don't** use more than two font weights on a screen.
- **Don't** mix sharp and rounded corners in the same view.
- **Don't** let JavaScript render primary content, fetch data client-side,
  or hold the bearer token — the token stays server-side, always.
- **Don't** render PII the remote API has masked; the dashboard never
  unmasks.
- **Don't** reach for animation beyond the single calm page-load rise
  (and honor `prefers-reduced-motion`).
