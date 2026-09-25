/**
 * The country layer: 24 country profiles, 51 patterns, 20 check digits.
 *
 * This implements the seven rules that `generated/sdk-registry/README.md`
 * marks **SDK**, from the bundle alone. Bundle 1.1.0 carries the data all seven
 * need -- the activation signals, the country map, the three windows, the
 * whole-word vocabulary, the near-miss policy, the table constants and the
 * reference labels -- so this SDK no longer generates an activation layer of
 * its own and no longer hard-codes a window. Everything below reads off
 * `./pii-registry`.
 *
 *   1. ACTIVATE. A country's patterns run only when one of its signals fires:
 *      the signal regex matches AND, where either keyword list is non-empty,
 *      a substring keyword appears anywhere in the lowercased document or a
 *      whole-word keyword appears on a word boundary. First signal per country
 *      wins; `activates` is pushed, not the country code.
 *   2. MATCH the regex, case-sensitively, globally.
 *   3. KEYWORD, when requiresKeyword. Whole-word first (symmetric
 *      `CONTEXT_WINDOW`), then the column verdict (rule 7), then the substring
 *      window -- which is ASYMMETRIC, `KEYWORD_WINDOW_BEFORE` before the match
 *      and `KEYWORD_WINDOW_AFTER` after it. The first that answers wins.
 *      Then rule 7b may close the gate again.
 *   4. CHECKSUM, when checksumRequired. Advisory checksums never reject.
 *   5. SUPERSEDE. A match that fully contains every range it overlaps takes
 *      them; a partial overlap is dropped. Containment is judged against the
 *      existing range's trimmed core. Pass your own L0 ranges as
 *      `existingRanges` and read `supersededRanges` back.
 *   6. NEAR MISS. A checksum-failing span that still reads as an identifier is
 *      held back and, if nothing else claimed it, redacted generically rather
 *      than released in clear.
 *   7. COLUMN HEADER. In a delimited table a bare value cell is judged by its
 *      column header -- and only by a header naming ONE country's identifier.
 *   7b. NEAREST LABEL. A commercial reference word closer to the number than
 *      any identifier word closes the gate. It can only ever close one.
 *
 * Still cloud-only, by design, and the same layers the SDK pages already name:
 * the universal (L0) patterns, the slot, context, gravity and name layers,
 * industry profiles and org configuration.
 */

import {
  TORK_PII_PATTERNS,
  TORK_PII_SIGNALS,
  TORK_PII_COUNTRIES,
  TORK_PII_REGISTRY_VERSION,
  TORK_PII_CONTENT_HASH,
  TORK_PII_KEYWORD_WINDOW_BEFORE,
  TORK_PII_KEYWORD_WINDOW_AFTER,
  TORK_PII_CONTEXT_WINDOW,
  TORK_PII_LABEL_WINDOW,
  TORK_PII_LABEL_REACH,
  TORK_PII_NEAR_MISS_REDACTION,
  TORK_PII_NEAR_MISS_TYPE,
  TORK_PII_GENERIC_ID_KEYWORDS,
  TORK_PII_LOCAL_ID_KEYWORDS,
  TORK_PII_REFERENCE_LABELS,
  TORK_PII_TABLE_DELIMITERS,
  TORK_PII_TABLE_MAX_HEADER_LENGTH,
  TORK_PII_TABLE_MAX_HEADER_WORDS,
  TORK_PII_TABLE_MIN_ROWS,
  TORK_PII_TABLE_MIN_COMMA_COLUMNS,
  type TorkPiiPattern,
} from './pii-registry';
import { CHECKSUM_FUNCTIONS } from './pii-checksums';

export { TORK_PII_REGISTRY_VERSION, TORK_PII_CONTENT_HASH };

/** Characters before a match that count as "nearby" for the substring keyword gate. */
export const KEYWORD_WINDOW_BEFORE = TORK_PII_KEYWORD_WINDOW_BEFORE;
/** Characters after a match that count as "nearby" for the substring keyword gate. */
export const KEYWORD_WINDOW_AFTER = TORK_PII_KEYWORD_WINDOW_AFTER;
/** The symmetric window: whole-word keywords and the near-miss gate. */
export const CONTEXT_WINDOW = TORK_PII_CONTEXT_WINDOW;

const NATIONAL_ID_KEYWORDS = [...TORK_PII_GENERIC_ID_KEYWORDS, ...TORK_PII_LOCAL_ID_KEYWORDS];
const GENERIC_SET = new Set(TORK_PII_GENERIC_ID_KEYWORDS);

export interface CountryPIIMatch {
  /** Registry pattern name, e.g. 'za_id_number'. */
  name: string;
  /** ISO 3166-1 alpha-2, or 'EU' for the bloc profile. */
  country: string;
  /** Shared redaction label, e.g. 'NATIONAL_ID'. The receipt block hashes labels. */
  label: string;
  /** Registry type, e.g. 'za_id_number' — or 'national_id_near_miss' for a rule 6 span. */
  type: string;
  redaction: string;
  startIndex: number;
  endIndex: number;
}

const BY_NAME = new Map<string, TorkPiiPattern>(TORK_PII_PATTERNS.map((p) => [p.name, p]));

const COUNTRY_PATTERNS: Record<string, string[]> = (() => {
  const m: Record<string, string[]> = {};
  for (const c of TORK_PII_COUNTRIES) m[c.code] = c.patterns;
  return m;
})();

const SIGNALS_BY_COUNTRY = (() => {
  const m = new Map<string, typeof TORK_PII_SIGNALS>();
  for (const s of TORK_PII_SIGNALS) {
    const list = m.get(s.country);
    if (list) list.push(s);
    else m.set(s.country, [s]);
  }
  return m;
})();

/** Countries in the order their first signal appears — the cloud's evaluation order. */
const SIGNAL_ORDER: string[] = (() => {
  const seen: string[] = [];
  for (const s of TORK_PII_SIGNALS) if (!seen.includes(s.country)) seen.push(s.country);
  return seen;
})();

// ── shared helpers ───────────────────────────────────────────────────────────

/** A pattern's whole vocabulary: the substring keywords and the whole-word ones. */
function allKeywordsOf(p: { keywords: string[]; wholeWordKeywords: string[] }): string[] {
  return p.wholeWordKeywords.length ? [...p.keywords, ...p.wholeWordKeywords] : p.keywords;
}

/** The half of a vocabulary that names ONE country's identifier. */
function specificKeywords(keywords: readonly string[] | undefined): string[] {
  if (!keywords?.length) return [];
  return keywords.filter((k) => !GENERIC_SET.has(k));
}

/** Rule 3, substring half: ASYMMETRIC — 60 before the match, 40 after it. */
function hasNearbyContext(content: string, start: number, end: number, keywords: readonly string[]): boolean {
  const before = content.substring(Math.max(0, start - KEYWORD_WINDOW_BEFORE), start).toLowerCase();
  const after = content.substring(end, Math.min(content.length, end + KEYWORD_WINDOW_AFTER)).toLowerCase();
  return keywords.some((kw) => before.includes(kw) || after.includes(kw));
}

/** Symmetric `CONTEXT_WINDOW` either side, substring. Used by rule 6. */
function hasContextAround(content: string, start: number, end: number, keywords: readonly string[]): boolean {
  const window = content
    .substring(Math.max(0, start - CONTEXT_WINDOW), Math.min(content.length, end + CONTEXT_WINDOW))
    .toLowerCase();
  return keywords.some((kw) => window.includes(kw));
}

/**
 * Rule 3, whole-word half: symmetric `CONTEXT_WINDOW`, with a boundary on each
 * side, a boundary being "not a letter or digit".
 *
 * This is the gate Indonesia needs. `nik` sits inside teknik, elektronik,
 * klinik and pabrik, so a substring test would open the gate on a sales ledger;
 * a boundary test catches "NIK 3171010101900001" and leaves "teknik" alone.
 */
export function hasWholeWordContextAround(
  content: string,
  start: number,
  end: number,
  words: readonly string[] | undefined,
): boolean {
  if (!words?.length) return false;
  const window = content
    .substring(Math.max(0, start - CONTEXT_WINDOW), Math.min(content.length, end + CONTEXT_WINDOW))
    .toLowerCase();
  for (const w of words) {
    let from = 0;
    for (;;) {
      const i = window.indexOf(w, from);
      if (i === -1) break;
      const before = i === 0 ? '' : window[i - 1];
      const after = i + w.length >= window.length ? '' : window[i + w.length];
      if (!/[a-z0-9]/.test(before) && !/[a-z0-9]/.test(after)) return true;
      from = i + 1;
    }
  }
  return false;
}

/** The same boundary test over a whole document, for rule 1. */
function documentHasWholeWord(content: string, words: readonly string[] | undefined): boolean {
  if (!words?.length) return false;
  return hasWholeWordContextAround(content, 0, content.length, words);
}

// ── rule 1: activation ───────────────────────────────────────────────────────

/**
 * The countries whose patterns this text activates, in the bundle's signal
 * order. Pure and local: no network, no clock.
 */
export function inferRegions(content: string): string[] {
  const regions: string[] = [];
  const lower = content.toLowerCase();
  for (const code of SIGNAL_ORDER) {
    const signals = SIGNALS_BY_COUNTRY.get(code);
    if (!signals) continue;
    for (const signal of signals) {
      // Fresh lastIndex on every use; these regexes are shared objects.
      signal.regex.lastIndex = 0;
      if (!signal.regex.test(content)) continue;
      const bySubstring = signal.keywords.length > 0 && signal.keywords.some((k) => lower.includes(k));
      const byWholeWord = documentHasWholeWord(content, signal.wholeWordKeywords);
      // Both lists empty means the shape alone is distinctive enough.
      if (signal.keywords.length > 0 || signal.wholeWordKeywords.length > 0) {
        if (!bySubstring && !byWholeWord) continue;
      }
      const target = signal.activates || code;
      if (!regions.includes(target)) regions.push(target);
      break; // one signal per country is enough
    }
  }
  return regions;
}

/** The patterns those regions switch on, de-duplicated, in registry order. */
export function patternsForRegions(regions: string[]): TorkPiiPattern[] {
  const out: TorkPiiPattern[] = [];
  const seen = new Set<string>();
  for (const code of regions) {
    for (const name of COUNTRY_PATTERNS[code.toUpperCase()] ?? []) {
      if (seen.has(name)) continue;
      const p = BY_NAME.get(name);
      if (!p) continue;
      seen.add(name);
      out.push(p);
    }
  }
  return out;
}

// ── rule 7: the column is the context ────────────────────────────────────────

interface TableScope {
  start: number;
  end: number;
  header: string;
  rowStart: number;
  rowEnd: number;
}

function looksLikeHeader(cells: string[], delimiter: string): boolean {
  if (cells.length < (delimiter === ',' ? TORK_PII_TABLE_MIN_COMMA_COLUMNS : 2)) return false;
  return cells.every((c) => {
    const t = c.trim();
    if (t.length === 0 || t.length > TORK_PII_TABLE_MAX_HEADER_LENGTH) return false;
    if (!/[A-Za-zÀ-￿]/.test(t)) return false;
    if (/^\+?[\d\s.\-/]+$/.test(t)) return false;
    if (/[.?!]/.test(t)) return false;
    return t.split(/\s+/).length <= TORK_PII_TABLE_MAX_HEADER_WORDS;
  });
}

/** The cells of `content`, when `content` is a delimited table with a header row. */
export function tableScopes(content: string): TableScope[] {
  const lines = content.split('\n');
  if (lines.length < TORK_PII_TABLE_MIN_ROWS) return [];

  const offsets: number[] = [];
  let at = 0;
  for (const line of lines) {
    offsets.push(at);
    at += line.length + 1;
  }

  for (const delimiter of TORK_PII_TABLE_DELIMITERS) {
    const headerCells = lines[0].split(delimiter);
    if (!looksLikeHeader(headerCells, delimiter)) continue;
    const width = headerCells.length;

    const dataRows: number[] = [];
    for (let i = 1; i < lines.length; i++) {
      if (lines[i].trim() === '') continue;
      if (lines[i].split(delimiter).length !== width) return [];
      dataRows.push(i);
    }
    if (dataRows.length < TORK_PII_TABLE_MIN_ROWS - 1) continue;

    const scopes: TableScope[] = [];
    for (const row of dataRows) {
      const cells = lines[row].split(delimiter);
      const rowStart = offsets[row];
      const rowEnd = rowStart + lines[row].length;
      let cellStart = rowStart;
      for (let col = 0; col < width; col++) {
        scopes.push({
          start: cellStart,
          end: cellStart + cells[col].length,
          header: headerCells[col].trim().toLowerCase(),
          rowStart,
          rowEnd,
        });
        cellStart += cells[col].length + delimiter.length;
      }
    }
    return scopes;
  }
  return [];
}

/** Whether `header` names the identifier — a whole-word match, not a substring. */
function headerNames(header: string, keywords: readonly string[]): boolean {
  for (const kw of keywords) {
    const i = header.indexOf(kw);
    if (i === -1) continue;
    const beforeOk = i === 0 || !/[a-z0-9]/.test(header[i - 1]);
    const afterIdx = i + kw.length;
    const afterOk = afterIdx >= header.length || !/[a-z0-9]/.test(header[afterIdx]);
    if (beforeOk && afterOk) return true;
  }
  return false;
}

function cellAt(scopes: readonly TableScope[], start: number, end: number): TableScope | null {
  for (const s of scopes) if (start >= s.start && end <= s.end) return s;
  return null;
}

/** null when the window should be consulted as usual. */
function columnVerdict(
  content: string,
  scopes: readonly TableScope[],
  start: number,
  end: number,
  allKeywords: readonly string[] | undefined,
  specific: readonly string[] | undefined,
): boolean | null {
  if (!scopes.length) return null;
  const cell = cellAt(scopes, start, end);
  if (!cell) return null;
  // A cell whose own row names the identifier is prose in a delimited block.
  const rowText = content.substring(cell.rowStart, cell.rowEnd).toLowerCase();
  if (allKeywords?.some((k) => rowText.includes(k))) return null;
  return specific?.length ? headerNames(cell.header, specific) : false;
}

// ── rule 7b: nearest label wins ──────────────────────────────────────────────

function closestBefore(before: string, keywords: readonly string[]): number | null {
  let best: number | null = null;
  for (const kw of keywords) {
    const i = before.lastIndexOf(kw);
    if (i === -1) continue;
    const distance = before.length - (i + kw.length);
    if (best === null || distance < best) best = distance;
  }
  return best;
}

function closestAfter(after: string, keywords: readonly string[]): number | null {
  let best: number | null = null;
  for (const kw of keywords) {
    const i = after.indexOf(kw);
    if (i === -1) continue;
    if (best === null || i < best) best = i;
  }
  return best;
}

/**
 * True when the number is labelled as a commercial reference more closely than
 * as an identifier, in which case the gate must not open. It can only ever
 * close a gate, so it cannot invent a redaction.
 */
export function labelledAsReference(
  content: string,
  start: number,
  end: number,
  identifierKeywords: readonly string[] | undefined,
): boolean {
  const before = content.substring(Math.max(0, start - TORK_PII_LABEL_WINDOW), start).toLowerCase();
  const ref = closestBefore(before, TORK_PII_REFERENCE_LABELS);
  if (ref === null || ref > TORK_PII_LABEL_REACH) return false;
  if (!identifierKeywords?.length) return true;
  const idBefore = closestBefore(before, identifierKeywords);
  if (idBefore !== null && idBefore <= ref) return false;
  const after = content.substring(end, Math.min(content.length, end + TORK_PII_LABEL_WINDOW)).toLowerCase();
  const idAfter = closestAfter(after, identifierKeywords);
  if (idAfter !== null && idAfter <= ref) return false;
  return true;
}

// ── the pass ─────────────────────────────────────────────────────────────────

/** The span with leading and trailing non-alphanumeric characters removed. */
function trimmedCore(content: string, start: number, end: number): [number, number] {
  let s = start;
  let e = end;
  while (s < e && !/[0-9A-Za-z]/.test(content[s])) s++;
  while (e > s && !/[0-9A-Za-z]/.test(content[e - 1])) e--;
  return s === e ? [start, end] : [s, e];
}

export interface CountryPIIResult {
  matches: CountryPIIMatch[];
  /** Ranges from `existingRanges` that a country match superseded (rule 5). */
  supersededRanges: [number, number][];
}

/**
 * Country matches for `content`, already de-overlapped, ordered by position.
 *
 * `patterns` bypasses activation (the per-pattern unit tests use it).
 * `existingRanges` are your own L0 spans, so rule 5 can supersede them.
 */
export function detectCountryPIIWithRanges(
  content: string,
  patterns?: TorkPiiPattern[],
  existingRanges: [number, number][] = [],
): CountryPIIResult {
  // Rule 1a: alwaysOn patterns (au_tfn, au_abn, au_medicare) are not gated by
  // rule 1's activation and run first, so an activated country pattern can
  // supersede one of theirs under rule 5. Only when the caller lets activation
  // run its course — an explicit `patterns` override (the per-pattern unit
  // tests) already names exactly what should run.
  const alwaysOn = patterns ? [] : TORK_PII_PATTERNS.filter((p) => p.alwaysOn);
  const regional = patterns ?? patternsForRegions(inferRegions(content));
  const alwaysOnNames = new Set(alwaysOn.map((p) => p.name));
  const active = [...alwaysOn, ...regional.filter((p) => !alwaysOnNames.has(p.name))];
  if (active.length === 0) return { matches: [], supersededRanges: [] };

  const tables = tableScopes(content);
  const activeExisting: [number, number][] = [...existingRanges];
  const supersededRanges: [number, number][] = [];
  const claimed: [number, number][] = [];
  const found: CountryPIIMatch[] = [];
  const nearMisses: { start: number; end: number }[] = [];

  for (const pattern of active) {
    const flags = pattern.regex.flags.includes('g') ? pattern.regex.flags : pattern.regex.flags + 'g';
    const re = new RegExp(pattern.regex.source, flags);
    let match: RegExpExecArray | null;
    while ((match = re.exec(content)) !== null) {
      // A zero-length match would spin forever.
      if (match[0].length === 0) {
        re.lastIndex++;
        continue;
      }
      const start = match.index;
      const end = start + match[0].length;

      // Rules 3, 7 and 7b.
      if (pattern.requiresKeyword && pattern.keywords.length > 0) {
        const all = allKeywordsOf(pattern);
        const whole = hasWholeWordContextAround(content, start, end, pattern.wholeWordKeywords);
        const column = columnVerdict(content, tables, start, end, all, specificKeywords(all));
        const ok = whole || (column !== null ? column : hasNearbyContext(content, start, end, pattern.keywords));
        if (!ok) continue;
        if (labelledAsReference(content, start, end, pattern.keywords)) continue;
      }

      // Rule 4, and rule 6's candidate.
      if (pattern.checksumRequired && pattern.checksum) {
        const fn = CHECKSUM_FUNCTIONS[pattern.checksum];
        if (fn && !fn(match[0])) {
          if (pattern.nearMissFallback) {
            const vocabulary = pattern.nearMissKeywords.length
              ? [...NATIONAL_ID_KEYWORDS, ...pattern.nearMissKeywords]
              : pattern.keywords.length
                ? [...NATIONAL_ID_KEYWORDS, ...pattern.keywords]
                : NATIONAL_ID_KEYWORDS;
            if (hasContextAround(content, start, end, vocabulary)) nearMisses.push({ start, end });
          }
          continue;
        }
      }

      // Rule 5.
      const allActive: [number, number][] = [...activeExisting, ...claimed];
      const overlapping = allActive.filter(([rs, rend]) => start < rend && end > rs);
      if (overlapping.length > 0) {
        const supersedesAll = overlapping.every(([rs, rend]) => {
          const [cs, ce] = trimmedCore(content, rs, rend);
          return start <= cs && end >= ce;
        });
        if (!supersedesAll) continue;
        for (const [os, oe] of overlapping) {
          const ei = activeExisting.findIndex(([rs, rend]) => rs === os && rend === oe);
          if (ei !== -1) {
            supersededRanges.push(activeExisting[ei]);
            activeExisting.splice(ei, 1);
          }
          const ci = claimed.findIndex(([rs, rend]) => rs === os && rend === oe);
          if (ci !== -1) {
            claimed.splice(ci, 1);
            const fi = found.findIndex((f) => f.startIndex === os && f.endIndex === oe);
            if (fi !== -1) found.splice(fi, 1);
          }
        }
      }

      claimed.push([start, end]);
      found.push({
        name: pattern.name,
        country: pattern.country,
        label: pattern.label,
        type: pattern.type,
        redaction: pattern.redaction,
        startIndex: start,
        endIndex: end,
      });
    }
  }

  // Rule 6, last: a near miss can only ever fill a hole.
  const taken: [number, number][] = [...activeExisting, ...claimed];
  for (const c of nearMisses) {
    if (taken.some(([rs, rend]) => c.start < rend && c.end > rs)) continue;
    taken.push([c.start, c.end]);
    found.push({
      name: TORK_PII_NEAR_MISS_TYPE,
      country: '',
      label: 'NATIONAL_ID',
      type: TORK_PII_NEAR_MISS_TYPE,
      redaction: TORK_PII_NEAR_MISS_REDACTION,
      startIndex: c.start,
      endIndex: c.end,
    });
  }

  found.sort((a, b) => a.startIndex - b.startIndex);
  return { matches: found, supersededRanges };
}

/** Country matches for `content`. The common case: no L0 ranges to supersede. */
export function detectCountryPII(content: string, patterns?: TorkPiiPattern[]): CountryPIIMatch[] {
  return detectCountryPIIWithRanges(content, patterns).matches;
}

/**
 * Replace every span in `spans` with its redaction, right to left.
 *
 * Right to left is what keeps the earlier indices valid, and splicing whole
 * spans in one pass is what guarantees no partial redaction: a digit can never
 * be left standing beside a redaction token, because nothing is ever matched
 * against text that a previous replacement has already rewritten.
 *
 * `spans` must not overlap. detectCountryPII guarantees that.
 */
export function applyRedactions(
  text: string,
  spans: { startIndex: number; endIndex: number; redaction: string }[],
): string {
  if (spans.length === 0) return text;
  const ordered = [...spans].sort((a, b) => a.startIndex - b.startIndex);
  let out = text;
  for (let i = ordered.length - 1; i >= 0; i--) {
    const s = ordered[i];
    out = out.slice(0, s.startIndex) + s.redaction + out.slice(s.endIndex);
  }
  return out;
}
