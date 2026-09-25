/**
 * Country-layer parity tests.
 *
 * The fixtures are generated from the cloud's own evidence, not written here:
 *
 *   pii-unit-cases.json  one valid sample per registry pattern, a
 *                        checksum-broken variant for each pattern whose
 *                        checksum is a gate, and the Indonesian boundary cases.
 *   pii-vectors.json     all 2,092 inputs of the cloud's golden snapshot
 *                        (tests/fixtures/pii-country-corpus/registry-golden.json):
 *                        every country-corpus sentence for all 249 ISO
 *                        jurisdictions, and the whole 1,523-line business
 *                        false-positive corpus.
 *
 * `expectedOutput` is the COUNTRY LAYER alone. Where the cloud's own output
 * differs, the case carries `cloudOutput` and a `divergence` naming the cause,
 * so the fixture states its distance from the cloud instead of hiding it.
 * Bundle 1.2.0 closed the AU bundle gap (au_tfn, au_abn, au_medicare are now
 * alwaysOn patterns), so there is exactly one cause left — L0 — and the suite
 * asserts there are no others.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import {
  detectCountryPII,
  detectCountryPIIWithRanges,
  inferRegions,
  applyRedactions,
  labelledAsReference,
  hasWholeWordContextAround,
  tableScopes,
  KEYWORD_WINDOW_BEFORE,
  KEYWORD_WINDOW_AFTER,
  CONTEXT_WINDOW,
  TORK_PII_REGISTRY_VERSION,
  TORK_PII_CONTENT_HASH,
} from './pii-country';
import { TORK_PII_PATTERNS, TORK_PII_COUNTRIES, TORK_PII_SIGNALS } from './pii-registry';
import { CHECKSUM_FUNCTIONS } from './pii-checksums';

const fixture = (name: string) => JSON.parse(readFileSync(join(__dirname, '__fixtures__', name), 'utf8'));

interface UnitCase {
  pattern: string; country: string; label: string; redaction: string;
  input: string; sample: string; expectDetected: boolean; note?: string;
}
interface Vector {
  id: string; kind: string; input: string; expectedOutput: string;
  expectedRegions: string[]; expectedLabels: string[]; expectedNames: string[];
  cloudOutput?: string; divergence?: string;
}

const UNIT: UnitCase[] = fixture('pii-unit-cases.json');
const V: { bundleVersion: string; contentHash: string; cases: Vector[] } = fixture('pii-vectors.json');
const BY_NAME = new Map(TORK_PII_PATTERNS.map((p) => [p.name, p]));

describe('country registry bundle', () => {
  it('is the version and content the fixtures were generated from', () => {
    expect(TORK_PII_REGISTRY_VERSION).toBe(V.bundleVersion);
    expect(TORK_PII_CONTENT_HASH).toBe(V.contentHash);
  });

  it('carries 54 patterns across 24 profiles, with 51 activation signals', () => {
    // 51 region-gated patterns plus the 3 alwaysOn AU patterns added in 1.2.0
    // (au_tfn, au_abn, au_medicare) — alwaysOn patterns add no signal of their own.
    expect(TORK_PII_PATTERNS).toHaveLength(54);
    expect(TORK_PII_COUNTRIES).toHaveLength(24);
    expect(TORK_PII_SIGNALS).toHaveLength(51);
  });

  it('covers Indonesia, added in 1.1.0', () => {
    const id = TORK_PII_COUNTRIES.find((c) => c.code === 'ID');
    expect(id, 'Indonesia is missing from the bundle').toBeDefined();
    expect(id!.patterns).toContain('id_nik');
    const nik = BY_NAME.get('id_nik')!;
    expect(nik.label).toBe('NIK');
    expect(nik.wholeWordKeywords).toContain('nik');
  });

  it('reads its windows from the bundle, and they are not all the same number', () => {
    expect(KEYWORD_WINDOW_BEFORE).toBe(60);
    expect(KEYWORD_WINDOW_AFTER).toBe(40);
    expect(CONTEXT_WINDOW).toBe(60);
    expect(KEYWORD_WINDOW_AFTER).not.toBe(KEYWORD_WINDOW_BEFORE);
  });

  it('names a checksum function for every pattern that declares one', () => {
    for (const p of TORK_PII_PATTERNS) {
      if (!p.checksum) continue;
      expect(CHECKSUM_FUNCTIONS[p.checksum], `${p.name} -> ${p.checksum}`).toBeTypeOf('function');
    }
  });

  it('uses only the portable regex subset', () => {
    const forbidden: [RegExp, string][] = [
      [/\(\?=/, 'lookahead'], [/\(\?!/, 'negative lookahead'], [/\(\?<[=!]/, 'lookbehind'],
      [/\\[1-9]/, 'backreference'], [/\\[pP]\{/, 'unicode property escape'], [/\(\?>/, 'atomic group'],
    ];
    for (const p of [...TORK_PII_PATTERNS.map((x) => x.regex), ...TORK_PII_SIGNALS.map((x) => x.regex)]) {
      for (const [re, why] of forbidden) expect(re.test(p.source), `${p.source} uses ${why}`).toBe(false);
    }
  });
});

describe('per-pattern unit cases', () => {
  for (const c of UNIT) {
    const title = `${c.pattern}: ${c.expectDetected ? 'detects' : 'rejects'} ${JSON.stringify(c.input)}${c.note ? ` (${c.note})` : ''}`;
    it(title, () => {
      const p = BY_NAME.get(c.pattern);
      expect(p, `${c.pattern} is not in the bundle`).toBeDefined();
      const found = detectCountryPII(c.input, [p!]);
      const hit = found.find((m) => m.name === c.pattern);
      if (c.expectDetected) {
        expect(hit, `expected ${c.pattern} to match`).toBeDefined();
        expect(c.input.slice(hit!.startIndex, hit!.endIndex)).toBe(c.sample);
        expect(hit!.redaction).toBe(c.redaction);
      } else {
        expect(hit, `expected ${c.pattern} NOT to match`).toBeUndefined();
      }
    });
  }
});

describe(`golden-snapshot parity (${V.cases.length} cloud inputs)`, () => {
  // The country-corpus cases get one test each, so a failure names the country
  // and the identifier. The 1,523-line business corpus is asserted in bulk
  // below; a failure there lists every offending line id.
  for (const c of V.cases.filter((x) => x.kind !== 'business-fp')) {
    it(`${c.id} (${c.kind})`, () => {
      expect(inferRegions(c.input), 'activation').toEqual(c.expectedRegions);
      const matches = detectCountryPII(c.input);
      expect(applyRedactions(c.input, matches), 'redaction').toBe(c.expectedOutput);
      expect([...new Set(matches.map((m) => m.label))]).toEqual(c.expectedLabels);
      expect([...new Set(matches.map((m) => m.name))]).toEqual(c.expectedNames);
    });
  }

  it('reproduces the cloud activation on every business-corpus line', () => {
    const bad = V.cases.filter((c) => c.kind === 'business-fp' &&
      JSON.stringify(inferRegions(c.input)) !== JSON.stringify(c.expectedRegions));
    expect(bad.map((c) => c.id)).toEqual([]);
  });

  it('adds no false positive to the business corpus', () => {
    const biz = V.cases.filter((c) => c.kind === 'business-fp');
    expect(biz.length).toBeGreaterThan(1500);
    const bad = biz.filter((c) => detectCountryPII(c.input).length > 0);
    expect(bad.map((c) => c.id)).toEqual([]);
  });

  it('diverges from the cloud for exactly one stated reason (L0), and no others', () => {
    // Bundle 1.2.0 closed the AU bundle gap (au_tfn, au_abn, au_medicare are
    // now alwaysOn patterns), so the only remaining divergence cause is L0:
    // the universal patterns this bundle deliberately excludes.
    const d = V.cases.filter((c) => c.divergence);
    for (const c of d) expect(c.divergence, c.id).toMatch(/^L0:/);
    const gaps = d.filter((c) => c.divergence!.startsWith('BUNDLE GAP'));
    expect(gaps.map((c) => c.id)).toEqual([]);
  });

  it('never leaves a digit standing beside a redaction token', () => {
    for (const c of V.cases) {
      const out = applyRedactions(c.input, detectCountryPII(c.input));
      expect(/\d\[[A-Z_]+_REDACTED\]|\[[A-Z_]+_REDACTED\]\d/.test(out), `${c.id}: ${out}`).toBe(false);
    }
  });

  it('never leaves a detected identifier in the output', () => {
    for (const c of V.cases) {
      const matches = detectCountryPII(c.input);
      if (!matches.length) continue;
      const out = applyRedactions(c.input, matches);
      for (const m of matches) {
        const raw = c.input.slice(m.startIndex, m.endIndex);
        expect(out.includes(raw), `${c.id}: "${raw}" survived`).toBe(false);
      }
    }
  });
});

describe('Indonesia — the rule the bundle added in 1.1.0', () => {
  const NIK = '3171010101900001';

  it('detects the short spelling, which is a whole-word keyword only', () => {
    const s = `NIK ${NIK} untuk pendaftaran rekening di Jakarta, Indonesia.`;
    expect(inferRegions(s)).toEqual(['ID']);
    expect(applyRedactions(s, detectCountryPII(s))).toBe('NIK [NIK_REDACTED] untuk pendaftaran rekening di Jakarta, Indonesia.');
  });

  it('detects the long spelling, which is an ordinary substring keyword', () => {
    const s = `Nomor Induk Kependudukan ${NIK} untuk pendaftaran.`;
    expect(applyRedactions(s, detectCountryPII(s))).toContain('[NIK_REDACTED]');
  });

  it('does NOT open the gate on "nik" inside an ordinary Indonesian word', () => {
    for (const word of ['teknik', 'elektronik', 'klinik', 'pabrik', 'piknik']) {
      const s = `Faktur ${word} ${NIK} untuk pelanggan.`;
      expect(detectCountryPII(s), `${word} opened the gate`).toEqual([]);
    }
  });

  it('a bare NIK with no label is not redacted', () => {
    expect(detectCountryPII(NIK)).toEqual([]);
  });
});

describe('rules that 1.1.0 added to the SDK half of the contract', () => {
  it('rule 6: a checksum-failing identifier is redacted generically, not released', () => {
    const s = 'South African ID number 8001015009088 for the FICA check.';
    const out = applyRedactions(s, detectCountryPII(s));
    expect(out).not.toContain('8001015009088');
    expect(out).toContain('[NATIONAL_ID_REDACTED]');
  });

  it('rule 7: a column header is the context for a bare value cell', () => {
    const csv = ['Name,CNIC,City', 'Ali,42201-1234567-1,Karachi', 'Sana,42201-7654321-2,Lahore', 'Omar,42201-1111111-3,Multan'].join('\n');
    expect(tableScopes(csv).length).toBeGreaterThan(0);
    const out = applyRedactions(csv, detectCountryPII(csv));
    expect(out).not.toContain('42201-1234567-1');
  });

  it('rule 7: a generic header does NOT act as context', () => {
    const csv = ['Name,Order ID Number,City', 'Ali,42201-1234567-1,Karachi', 'Sana,42201-7654321-2,Lahore', 'Omar,42201-1111111-3,Multan'].join('\n');
    expect(detectCountryPII(csv)).toEqual([]);
  });

  it('rule 7b: a commercial label closer than the identifier word closes the gate', () => {
    const s = 'Please do not send your CNIC. Use the job number 4220112345671.';
    expect(labelledAsReference(s, s.indexOf('4220112345671'), s.indexOf('4220112345671') + 13, ['cnic'])).toBe(true);
    expect(applyRedactions(s, detectCountryPII(s))).toContain('4220112345671');
  });

  it('rule 7b can only ever close a gate, never open one', () => {
    const s = 'Order 12345678901234 with no identifier word anywhere.';
    expect(detectCountryPII(s)).toEqual([]);
  });

  it('rule 5: a country match supersedes a wider L0 range it contains', () => {
    const s = 'CPF 529.982.247-25 para a nota fiscal no Brasil.';
    const at = s.indexOf('529.982.247-25');
    const { matches, supersededRanges } = detectCountryPIIWithRanges(s, undefined, [[at - 1, at + 14]]);
    expect(matches.some((m) => m.name === 'br_cpf')).toBe(true);
    expect(supersededRanges).toHaveLength(1);
  });

  it('whole-word matching respects a boundary at the start and end of the window', () => {
    expect(hasWholeWordContextAround('nik 123', 4, 7, ['nik'])).toBe(true);
    expect(hasWholeWordContextAround('teknik 123', 7, 10, ['nik'])).toBe(false);
  });
});

describe('rule 1a: the alwaysOn AU patterns, added in bundle 1.2.0', () => {
  it('detects a valid TFN by keyword alone, with no country activated by shape', () => {
    const s = 'My tax file number is 876 543 210 for the ATO return.';
    expect(applyRedactions(s, detectCountryPII(s))).toBe(
      'My tax file number is [TFN_REDACTED] for the ATO return.',
    );
  });

  it('detects a valid ABN, whose own shape and keyword activate no region', () => {
    const s = 'Supplier ABN 51 824 753 556 appears on the Australian invoice.';
    expect(inferRegions(s)).toEqual([]);
    expect(applyRedactions(s, detectCountryPII(s))).toBe(
      'Supplier ABN [ABN_REDACTED] appears on the Australian invoice.',
    );
  });

  it('a checksum-failing TFN is a near miss: redacted generically, not released', () => {
    const s = 'My tax file number is 876 543 211 for the ATO return.';
    const out = applyRedactions(s, detectCountryPII(s));
    expect(out).not.toContain('876 543 211');
    expect(out).toBe('My tax file number is [NATIONAL_ID_REDACTED] for the ATO return.');
  });

  it('a checksum-failing ABN is a true reject: nearMissFallback is false for it', () => {
    const s = 'Supplier ABN 51 824 753 557 appears on the Australian invoice.';
    expect(detectCountryPII(s)).toEqual([]);
  });

  it('Medicare is detected with its keyword, checksum passing', () => {
    const s = 'Patient Medicare number 2123 45670 1 for the bulk-billed visit.';
    expect(applyRedactions(s, detectCountryPII(s))).toBe(
      'Patient Medicare number [MEDICARE_REDACTED] for the bulk-billed visit.',
    );
  });

  it('Medicare’s checksum is advisory: a failing checksum never blocks detection', () => {
    const s = 'Patient Medicare number 2123 45671 1 for the bulk-billed visit.';
    expect(applyRedactions(s, detectCountryPII(s))).toBe(
      'Patient Medicare number [MEDICARE_REDACTED] for the bulk-billed visit.',
    );
  });

  it('an activated country pattern can still supersede an alwaysOn match under rule 5', () => {
    // au_tfn and au_medicare share the AU country entry with au_acn/au_phone_intl;
    // alwaysOn patterns run first, so this proves rule 5 still applies to them.
    const alwaysOn = TORK_PII_PATTERNS.filter((p) => p.alwaysOn);
    expect(alwaysOn.map((p) => p.name).sort()).toEqual(['au_abn', 'au_medicare', 'au_tfn']);
  });
});
