/**
 * Check digits for the country registry.
 *
 * The SDK bundle NAMES twenty algorithms and gives weights and a modulus for
 * the eleven that reduce to them; the other nine are marked `kind: "custom"`
 * and carry no specification, so they are ported here by hand from
 * landing/lib/pii/checksums.ts -- the single implementation the cloud and the
 * country corpus both use. Keeping the arithmetic identical is what makes a
 * receipt block from this SDK byte-identical to one from the cloud.
 *
 * Every function is pure: a string in, a boolean out. No BigInt, no Intl, no
 * clock, no I/O.
 */

const digitsOf = (s: string): string => s.replace(/\D/g, '');

/** Remainder of a long decimal digit string modulo m, digit by digit (no BigInt). */
const modDigits = (digits: string, m: number): number => {
  let r = 0;
  for (const ch of digits) r = (r * 10 + Number(ch)) % m;
  return r;
};

/** Luhn / ISO-IEC 7812-1 mod-10. */
export function luhn(input: string): boolean {
  const d = digitsOf(input);
  if (d.length < 2) return false;
  let sum = 0;
  let dbl = false;
  for (let i = d.length - 1; i >= 0; i--) {
    let n = Number(d[i]);
    if (dbl) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    dbl = !dbl;
  }
  return sum % 10 === 0;
}

const VERHOEFF_MUL = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
  [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
  [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];

const VERHOEFF_PERM = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
  [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
  [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

/** Verhoeff (Aadhaar, UIDAI Circular No. 1 of 2018). */
export function verhoeff(input: string): boolean {
  const d = digitsOf(input);
  let c = 0;
  const rev = d.split('').reverse();
  for (let i = 0; i < rev.length; i++) c = VERHOEFF_MUL[c][VERHOEFF_PERM[i % 8][Number(rev[i])]];
  return c === 0;
}

/** Australian TFN (ATO): weights 1,4,3,7,5,8,6,9,10 over 9 digits, sum mod 11 == 0. */
export function auTfn(input: string): boolean {
  const d = digitsOf(input);
  if (d.length !== 9) return false;
  const w = [1, 4, 3, 7, 5, 8, 6, 9, 10];
  return d.split('').reduce((s, c, i) => s + Number(c) * w[i], 0) % 11 === 0;
}

/** Australian ABN (ABR): subtract 1 from the first digit, weights 10,1,3..19, sum mod 89 == 0. */
export function auAbn(input: string): boolean {
  const d = digitsOf(input);
  if (d.length !== 11) return false;
  const w = [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19];
  const first = Number(d[0]) - 1;
  const sum = first * w[0] + d.slice(1).split('').reduce((s, c, i) => s + Number(c) * w[i + 1], 0);
  return sum % 89 === 0;
}

/** Australian Medicare (Services Australia): weights 1,3,7,9,1,3,7,9 over digits 1-8, mod 10 == digit 9. */
export function auMedicare(input: string): boolean {
  const d = digitsOf(input);
  if (d.length < 10) return false;
  if (!'23456'.includes(d[0])) return false;
  const w = [1, 3, 7, 9, 1, 3, 7, 9];
  const sum = d.slice(0, 8).split('').reduce((s, c, i) => s + Number(c) * w[i], 0);
  return sum % 10 === Number(d[8]);
}

/** UK NHS number (NHS Data Model and Dictionary): weights 10..2, check = 11 - (sum mod 11); 11 -> 0; 10 invalid. */
export function ukNhs(input: string): boolean {
  const d = digitsOf(input);
  if (d.length !== 10) return false;
  const sum = d.slice(0, 9).split('').reduce((s, c, i) => s + Number(c) * (10 - i), 0);
  let check = 11 - (sum % 11);
  if (check === 11) check = 0;
  if (check === 10) return false;
  return check === Number(d[9]);
}

/** Brazil CPF (Receita Federal): two sequential mod-11 check digits. */
export function brCpf(input: string): boolean {
  const d = digitsOf(input);
  if (d.length !== 11 || /^(\d)\1{10}$/.test(d)) return false;
  const calc = (len: number) => {
    let sum = 0;
    for (let i = 0; i < len; i++) sum += Number(d[i]) * (len + 1 - i);
    const r = (sum * 10) % 11;
    return r === 10 ? 0 : r;
  };
  return calc(9) === Number(d[9]) && calc(10) === Number(d[10]);
}

/** Brazil CNPJ (Receita Federal): two mod-11 check digits with different weight vectors. */
export function brCnpj(input: string): boolean {
  const d = digitsOf(input);
  if (d.length !== 14 || /^(\d)\1{13}$/.test(d)) return false;
  const calc = (weights: number[]) => {
    const sum = weights.reduce((s, w, i) => s + Number(d[i]) * w, 0);
    const r = sum % 11;
    return r < 2 ? 0 : 11 - r;
  };
  return (
    calc([5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]) === Number(d[12]) &&
    calc([6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]) === Number(d[13])
  );
}

/** Japan My Number (MIC Ordinance No. 85 of 2014). */
export function jpMyNumber(input: string): boolean {
  const d = digitsOf(input);
  if (d.length !== 12) return false;
  let sum = 0;
  for (let n = 1; n <= 11; n++) {
    const p = Number(d[11 - n]);
    const q = n <= 6 ? n + 1 : n - 5;
    sum += p * q;
  }
  const r = sum % 11;
  const check = r <= 1 ? 0 : 11 - r;
  return check === Number(d[11]);
}

/** China resident ID (GB 11643-1999): ISO 7064 MOD 11-2 over 17 digits, check in 0-9 or X. */
export function cnResidentId(input: string): boolean {
  const s = input.replace(/\s/g, '').toUpperCase();
  if (!/^\d{17}[\dX]$/.test(s)) return false;
  const w = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
  const sum = s.slice(0, 17).split('').reduce((acc, c, i) => acc + Number(c) * w[i], 0);
  return '10X98765432'[sum % 11] === s[17];
}

/**
 * Korea RRN, for numbers issued before 20 Oct 2020.
 *
 * ADVISORY ONLY, never a gate: numbers issued from 20 Oct 2020 are randomly
 * assigned and carry no check digit, so rejecting on this would stop detecting
 * every RRN issued since.
 */
export function krRrn(input: string): boolean {
  const d = digitsOf(input);
  if (d.length !== 13) return false;
  const w = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5];
  const sum = d.slice(0, 12).split('').reduce((s, c, i) => s + Number(c) * w[i], 0);
  return (11 - (sum % 11)) % 10 === Number(d[12]);
}

/** Singapore NRIC/FIN (ICA): weights 2,7,6,5,4,3,2 and a prefix-dependent letter table. */
export function sgNric(input: string): boolean {
  const s = input.replace(/\s/g, '').toUpperCase();
  if (!/^[STFGM]\d{7}[A-Z]$/.test(s)) return false;
  const w = [2, 7, 6, 5, 4, 3, 2];
  let sum = s.slice(1, 8).split('').reduce((acc, c, i) => acc + Number(c) * w[i], 0);
  const prefix = s[0];
  if (prefix === 'T' || prefix === 'G') sum += 4;
  if (prefix === 'M') sum += 3;
  const st = 'JZIHGFEDCBA';
  const fg = 'XWUTRQPNMLK';
  const m = 'KLJNPQRTUWX';
  const table = prefix === 'S' || prefix === 'T' ? st : prefix === 'M' ? m : fg;
  return table[sum % 11] === s[8];
}

const CF_ODD: Record<string, number> = {
  '0': 1, '1': 0, '2': 5, '3': 7, '4': 9, '5': 13, '6': 15, '7': 17, '8': 19, '9': 21,
  A: 1, B: 0, C: 5, D: 7, E: 9, F: 13, G: 15, H: 17, I: 19, J: 21, K: 2, L: 4, M: 18,
  N: 20, O: 11, P: 3, Q: 6, R: 8, S: 12, T: 14, U: 16, V: 10, W: 22, X: 25, Y: 24, Z: 23,
};

/** Italy codice fiscale (Agenzia delle Entrate): odd/even position tables, check letter. */
export function itCodiceFiscale(input: string): boolean {
  const s = input.replace(/\s/g, '').toUpperCase();
  if (!/^[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]$/.test(s)) return false;
  const even = (c: string) => (/\d/.test(c) ? Number(c) : c.charCodeAt(0) - 65);
  let sum = 0;
  for (let i = 0; i < 15; i++) sum += i % 2 === 0 ? CF_ODD[s[i]] : even(s[i]);
  return String.fromCharCode(65 + (sum % 26)) === s[15];
}

/** France NIR (Insee): 97-complement, Corsican 2A/2B mapped to 19/18 first. */
export function frNir(input: string): boolean {
  let s = input.replace(/\s/g, '').toUpperCase();
  if (!/^[12]\d{2}\d{2}(\d{2}|2A|2B)\d{3}\d{3}\d{2}$/.test(s)) return false;
  s = s.replace('2A', '19').replace('2B', '18');
  const body = s.slice(0, 13);
  const key = Number(s.slice(13));
  return 97 - modDigits(body, 97) === key;
}

/** Germany Steuer-IdNr (BZSt): ISO 7064 MOD 11,10 over 10 digits. */
export function deSteuerId(input: string): boolean {
  const d = digitsOf(input);
  if (d.length !== 11 || d[0] === '0') return false;
  let product = 10;
  for (let i = 0; i < 10; i++) {
    let sum = (Number(d[i]) + product) % 10;
    if (sum === 0) sum = 10;
    product = (sum * 2) % 11;
  }
  let check = 11 - product;
  if (check === 10) check = 0;
  return check === Number(d[10]);
}

/** Thailand national ID (DOPA): weights 13..2 over 12 digits, check = (11 - sum mod 11) mod 10. */
export function thNationalId(input: string): boolean {
  const d = digitsOf(input);
  if (d.length !== 13) return false;
  const sum = d.slice(0, 12).split('').reduce((s, c, i) => s + Number(c) * (13 - i), 0);
  return (11 - (sum % 11)) % 10 === Number(d[12]);
}

/** Canada SIN (Service Canada): Luhn over 9 digits. Advisory -- the algorithm is community-sourced. */
export const caSin = (input: string): boolean => digitsOf(input).length === 9 && luhn(input);

/** South Africa ID (Home Affairs / SARS BRS Appendix B 8.3): Luhn over 13 digits. */
export const zaId = (input: string): boolean => digitsOf(input).length === 13 && luhn(input);

/** UAE Emirates ID (ICP): Luhn over 15 digits starting 784. Advisory -- community-sourced. */
export const aeEmiratesId = (input: string): boolean => {
  const d = digitsOf(input);
  return d.length === 15 && d.startsWith('784') && luhn(d);
};

/** Saudi national ID / iqama: Luhn over 10 digits starting 1 or 2. Advisory -- community-sourced. */
export const saNationalId = (input: string): boolean => {
  const d = digitsOf(input);
  return d.length === 10 && /^[12]/.test(d) && luhn(d);
};

/** Keyed by the bundle's `checksum` field. */
export const CHECKSUM_FUNCTIONS: Record<string, (input: string) => boolean> = {
  luhn,
  verhoeff,
  au_tfn: auTfn,
  au_abn: auAbn,
  au_medicare: auMedicare,
  uk_nhs: ukNhs,
  br_cpf: brCpf,
  br_cnpj: brCnpj,
  jp_my_number: jpMyNumber,
  cn_resident_id: cnResidentId,
  kr_rrn: krRrn,
  sg_nric: sgNric,
  it_codice_fiscale: itCodiceFiscale,
  fr_nir: frNir,
  de_steuer_id: deSteuerId,
  th_national_id: thNationalId,
  ca_sin: caSin,
  za_id: zaId,
  ae_emirates_id: aeEmiratesId,
  sa_national_id: saNationalId,
};
