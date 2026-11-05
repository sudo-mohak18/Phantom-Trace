/**
 * Internationalized Domain Name (IDN) Homograph and Confusable Detection
 * Identifies mixed-script attacks, Cyrillic/Greek lookalikes, and Punycode spoofing.
 */

// Common Cyrillic and Greek homoglyphs mapped to Latin equivalents
const HOMOGLYPH_MAP: Record<string, string> = {
  // Cyrillic small letters
  '\u0430': 'a', // Cyrillic 'a'
  '\u0441': 'c', // Cyrillic 'es'
  '\u0435': 'e', // Cyrillic 'ie'
  '\u0456': 'i', // Cyrillic Byelorussian-Ukrainian 'i'
  '\u0458': 'j', // Cyrillic 'je'
  '\u043E': 'o', // Cyrillic 'o'
  '\u0440': 'p', // Cyrillic 'er'
  '\u0455': 's', // Cyrillic 'dze'
  '\u0445': 'x', // Cyrillic 'ha'
  '\u0443': 'y', // Cyrillic 'u'
  // Cyrillic capital letters
  '\u0410': 'A',
  '\u0412': 'B',
  '\u0421': 'C',
  '\u0415': 'E',
  '\u041D': 'H',
  '\u0406': 'I',
  '\u041C': 'M',
  '\u041E': 'O',
  '\u0420': 'P',
  '\u0422': 'T',
  '\u0425': 'X',
  // Greek small letters
  '\u03B1': 'a', // Greek alpha
  '\u03BF': 'o', // Greek omicron
  '\u03BD': 'v', // Greek nu
  '\u03C1': 'p', // Greek rho
};

export interface HomographCheckResult {
  detected: boolean;
  isPunycode: boolean;
  punycodeText: string | null;
  normalizedDomain: string;
  replacedCharacters: Array<{ original: string; replacedWith: string; codePoint: string }>;
  details: string;
}

export function detectHomographAttack(domain: string): HomographCheckResult {
  const isPunycode = domain.toLowerCase().includes('xn--');
  const replaced: Array<{ original: string; replacedWith: string; codePoint: string }> = [];

  let normalized = '';
  let containsNonAscii = false;

  for (const char of domain) {
    const code = char.charCodeAt(0);
    if (code > 127) {
      containsNonAscii = true;
      if (HOMOGLYPH_MAP[char]) {
        replaced.push({
          original: char,
          replacedWith: HOMOGLYPH_MAP[char],
          codePoint: `U+${char.charCodeAt(0).toString(16).padStart(4, '0').toUpperCase()}`,
        });
        normalized += HOMOGLYPH_MAP[char];
      } else {
        normalized += char;
      }
    } else {
      normalized += char;
    }
  }

  const detected = isPunycode || replaced.length > 0;
  let details = 'No homograph or punycode indicators detected.';

  if (isPunycode) {
    details = `Domain uses Punycode encoding (${domain}) which can disguise character substitution or non-Latin lookalike scripts.`;
  } else if (replaced.length > 0) {
    const charList = replaced.map(r => `'${r.original}' (${r.codePoint} -> '${r.replacedWith}')`).join(', ');
    details = `Detected ${replaced.length} suspicious non-Latin homoglyph(s): ${charList}. This is a classic visual spoofing technique.`;
  }

  return {
    detected,
    isPunycode,
    punycodeText: isPunycode ? domain : null,
    normalizedDomain: normalized,
    replacedCharacters: replaced,
    details,
  };
}
