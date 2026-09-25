# Changelog

All notable changes to the Tork Governance JavaScript SDK will be documented in this file.

## [0.13.0] - 2026-09-25

### Added
- **The country layer: 24 country profiles, 51 patterns, 20 check digits.** The
  detector no longer carries a hand-written, US-shaped pattern subset. The
  patterns, keywords, redaction labels and checksum gates are generated from the
  cloud's own country registry and consumed verbatim from the SDK bundle
  (`generated/sdk-registry`, `Registry-Version: 1.2.0`, content `cfd4f61ebaf45e74`). Countries covered: AU,
  US, GB, EU, AE, SA, NG, IN, JP, CN, KR, BR, CA, ZA, GH, IT, KE, MU, MX, MY,
  PK, SG, TH, ID.
- **PII registry bundle 1.2.0 (24 countries, incl. AU TFN/ABN/Medicare).** The
  bundle's three `alwaysOn` patterns — `au_tfn`, `au_abn`, `au_medicare` — now
  run unconditionally, before country activation, exactly as rule 1a specifies:
  Australia's TFN and ABN both gate on a required checksum (a checksum failure
  is a near miss for the TFN, a true reject for the ABN), and the Medicare
  number's checksum is advisory only and never blocks detection. This closes
  the "AU bundle gap" the golden-snapshot parity suite measured against
  1.1.0 — it is now 0.
- New exports, all pure and local: `detectCountryPII`, `inferRegions`,
  `patternsForRegions`, `applyRedactions`, `CHECKSUM_FUNCTIONS`,
  `TORK_PII_PATTERNS`, `TORK_PII_REGISTRY_VERSION`, `KEYWORD_WINDOW_BEFORE`,
  `KEYWORD_WINDOW_AFTER`, and the `CountryPIIMatch` / `TorkPiiPattern` types.
- `PIIDetectionResult` gains three optional fields — `countryMatches`,
  `countryLabels`, `regions`. Nothing was removed or renamed, and `PIIType`
  stays the closed ten-value union so an exhaustive `switch` still compiles.
- **Nine check digits ported by hand.** The bundle names twenty algorithms and
  specifies the eleven that reduce to a weight vector and a modulus; the other
  nine (`br_cpf`, `br_cnpj`, `cn_resident_id`, `de_steuer_id`, `fr_nir`,
  `it_codice_fiscale`, `jp_my_number`, `kr_rrn`, `sg_nric`) are ported from
  `landing/lib/pii/checksums.ts`, each tested against the issuing authority's
  own worked example where one is published.

### Fixed
- **SDK-JS-PARTIAL-REDACTION.** Until 0.12.0 each PII type was redacted with its
  own `String.replace` over text a previous type had already rewritten, while
  `matches` carried indices into the *original* text. Two types matching
  overlapping spans could leave half an identifier standing beside a redaction
  token — digits exposed in output the caller had been told was redacted. Every
  match is now collected against the original text, overlaps are resolved before
  anything is rewritten, and the surviving spans are spliced right to left in a
  single pass. Two tests assert the invariant across all 2,092 vectors: no
  detected identifier survives in the output, and no digit is ever left adjacent
  to a redaction token.

### Notes
- **The bundle now states the whole contract, and this SDK implements it.**
  Bundle 1.0.0's README documented three rules; measured against the cloud's
  golden snapshot they disagreed with it on 14 of 86 country-corpus cases, so
  this SDK carried two more of its own. Bundle **1.1.0 documents seven**, marks
  each SDK or cloud-only, and ships the data all seven need in every language
  file -- the activation signals, the country map, the asymmetric 60/40 window,
  the symmetric 60 context window, the whole-word vocabulary, the near-miss
  policy, the table constants and the reference labels. So the locally generated
  activation layer is **deleted**, no window is hard-coded any more, and rules 6
  (near miss), 7 (column header) and 7b (nearest label) are implemented here for
  the first time. Every rule now reads its data off the placed bundle.
- Checksums that the issuing authority does not publish stay **advisory** and
  never reject a match: `ca_sin`, `emirates_id`, `de_tax_id`, `kr_rrn`,
  `sa_national_id`. Korea stopped issuing check digits on 20 Oct 2020.
- Not ported, and still cloud-only: the slot, context,
  gravity and name layers, industry profiles, and org configuration.
- 996 tests pass (329 before this release).
- **Indonesia is the country 1.1.0 added, and it is the one that proves the
  whole-word rule.** `id_nik`'s only short spellings -- NIK, KTP, NPWP -- are
  `wholeWordKeywords`, not ordinary keywords, because `nik` sits inside
  *teknik*, *elektronik*, *klinik* and *pabrik*. Matching them by substring
  would open the gate on an Indonesian sales ledger; matching them on a word
  boundary catches "NIK 3171010101900001" and leaves *teknik* alone. An SDK that
  merged the two lists would be shipping a false-positive bug, so the boundary
  test is implemented rather than the shortcut, and four unit cases assert both
  halves.
- **FLAGGED, upstream: bundle 1.1.0 cannot detect Australia's TFN, ABN or
  Medicare number.** `checksums.json` declares `au_tfn` and `au_abn` as
  `requiredBy` and `au_medicare` as `advisoryFor` patterns of those names, and
  `patterns` ships none of them -- the AU profile carries only `au_acn` and
  `au_phone_intl`. The AU activation signals are still keyed on "tfn", "tax
  file" and "medicare", so the bundle switches Australia on for identifiers it
  then has no pattern to catch. The cloud detects all three. This is a recall
  gap no SDK can close from the bundle, and the six parity cases it costs are
  recorded in the fixture as `BUNDLE GAP` rather than silently accepted.

## [0.12.0] - 2026-09-02

### Added
- **`scanToolResult()`** — scan a tool result (MCP server response, or any external
  system's output) for PII and prompt injection **before** it is appended to model
  context. On-device and synchronous: zero network calls, payload never leaves the
  machine. Available as a standalone function and as `Tork#scanToolResult`, which
  additionally produces a receipt.
- **PII detection reuses the existing on-device detector** (`detectPII`) — no second
  scanner. It moved to `src/pii.ts` so the scanner can import it without a cycle;
  `detectPII`, `PII_PATTERNS` and the PII types are still exported from the package
  entry, unchanged.
- **Prompt-injection heuristics** (`tork-injection-heuristics-v1`) — a conservative
  pattern set covering instruction override, role reassignment, and exfiltration
  URLs. The SDK had none before. Every injection finding is typed
  `heuristic:<name>` so a pattern match can never be read as a verified
  determination.
- **`receipt.tool_result_scan`** — records the scan as a client-attested, edge-captured
  control: `attested_by: 'client'`, `capture_mode: 'edge'`, counts by kind and type,
  tool name, server URI, blocked flag, and SDK version. Counts only — never the
  payload, a matched value, or a location path.
- `options.blockOnInjection` — when the heuristics fire, block the result: `sanitized`
  becomes `null` and `reason` explains the block.

### Notes
- Tool-result scanning is a **client-side, client-attested** control. Gateway-side
  enforcement is a separate, later control.
- The `tool_result_scan` block is local to the receipt. `POST /api/v1/attestations`
  validates a fixed field set with no column for it, so it is deliberately not
  transmitted; the attestation carries only the decision, PII type labels and count
  the endpoint already accepts.

## [0.10.0] - 2026-03-11

### Added
#### Mastra Adapter
- **TorkMastraAgent** — Governed agent wrapper for Mastra
- **TorkMastraToolWrapper** — Tool governance wrapper
- **governMastraWorkflow** — Workflow step middleware
- **mastraGoverned** — Decorator for agent.generate() calls
- Full support for streaming and async patterns

#### Microsoft Agent Framework Adapter
- **TorkMicrosoftAgent** — Governed agent wrapper
- **TorkMicrosoftToolWrapper** — Tool governance wrapper
- **governAgentChat** — Multi-agent chat governance
- **microsoftAgentGoverned** — Decorator for agent invocations
- Full support for A2A, MCP, and AG-UI patterns

## [0.9.2] - 2026-03-09

### Added
- feat: agent/session context fields (agent_id, agent_role, session_id, session_turn)

## [0.7.0] - 2026-02-03

### Added
- **tRPC adapter** (`trpc.ts`) - Type-safe API governance with middleware and transformers
- **Socket.io adapter** (`socketio.ts`) - Real-time WebSocket governance for Socket.io servers
- **GraphQL Yoga adapter** (`graphql-yoga.ts`) - GraphQL server governance with plugin and resolver support
- **ws WebSocket adapter** (`ws.ts`) - Native WebSocket governance for ws library

### Changed
- Enhanced Hono adapter with improved type definitions

## [0.6.0] - 2026-02-03

### Added
- **Deno Fresh adapter** (`fresh.ts`) - Middleware and handler governance for Deno Fresh
- **Bun.serve adapter** (`bun.ts`) - Native Bun server governance with router support

## [0.5.0] - 2026-02-03

### Added
- **Astro adapter** (`astro.ts`) - Middleware and API route governance for Astro
- **Elysia adapter** (`elysia.ts`) - Plugin-based governance for Elysia (Bun framework)

## [0.4.0] - 2026-02-03

### Added
- **Remix adapter** (`remix.ts`) - Loader and action governance for Remix applications
- **SvelteKit adapter** (`sveltekit.ts`) - Load function and form action governance
- **Nuxt adapter** (`nuxt.ts`) - H3 event handler and Nuxt plugin governance

## [0.3.0] - 2026-02-01

### Added
- NestJS adapter with module, guard, and interceptor support
- LangChain.js adapter with chain and callback governance
- Vercel AI SDK adapter

## [0.2.0] - 2026-01-15

### Added
- Hapi adapter with plugin-based governance
- Next.js adapter with middleware and route handler support

## [0.1.0] - 2026-01-01

### Added
- Initial release
- Core governance engine with PII detection
- Express middleware adapter
- Fastify plugin adapter
- Koa middleware adapter
- Hono middleware adapter
- Cryptographic receipt generation
