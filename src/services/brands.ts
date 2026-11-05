/**
 * Brand Impersonation & Typosquatting Detection Engine
 * 
 * CRITICAL RULE:
 * Official brand domains must NEVER be flagged as malicious or impersonated.
 * Official TLDs supported: .com, .net, .org, .io, .co, .us, .uk, .ca, .de, .fr, .jp, .me
 */

export interface BrandProfile {
  name: string;
  officialRoots: string[]; // e.g. ['paypal', 'paypal.me']
  officialDomains: string[]; // e.g. ['paypal.com', 'paypal.me', 'paypal-corp.com']
  commonKeywords: string[]; // keywords attackers append: 'security', 'login', 'verify', 'account'
}

export const KNOWN_BRANDS: BrandProfile[] = [
  {
    name: 'PayPal',
    officialRoots: ['paypal'],
    officialDomains: ['paypal.com', 'paypal.me', 'paypal-communication.com', 'paypalobjects.com'],
    commonKeywords: ['login', 'verify', 'security', 'billing', 'confirm', 'wallet', 'resolve', 'invoice'],
  },
  {
    name: 'Google',
    officialRoots: ['google', 'gmail', 'youtube'],
    officialDomains: [
      'google.com',
      'google.co.uk',
      'google.ca',
      'google.de',
      'google.org',
      'accounts.google.com',
      'gmail.com',
      'youtube.com',
      'googledrive.com',
      'gstatic.com',
    ],
    commonKeywords: ['drive', 'docs', 'verify', 'security', 'storage', 'auth', 'recovery'],
  },
  {
    name: 'Microsoft',
    officialRoots: ['microsoft', 'office', 'live', 'outlook', 'microsoftonline', 'azure'],
    officialDomains: [
      'microsoft.com',
      'microsoftonline.com',
      'office.com',
      'live.com',
      'outlook.com',
      'azure.com',
      'sharepoint.com',
      'onedrive.com',
      'msn.com',
      'windows.com',
    ],
    commonKeywords: ['login', '365', 'portal', 'sharepoint', 'auth', 'mfa', 'compliance', 'admin'],
  },
  {
    name: 'Apple',
    officialRoots: ['apple', 'icloud'],
    officialDomains: ['apple.com', 'icloud.com', 'appleid.apple.com', 'me.com'],
    commonKeywords: ['id', 'verify', 'support', 'locked', 'findmy', 'itunes', 'billing'],
  },
  {
    name: 'Amazon',
    officialRoots: ['amazon', 'aws'],
    officialDomains: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.ca', 'amazon.co.jp', 'aws.amazon.com', 'media-amazon.com'],
    commonKeywords: ['order', 'delivery', 'prime', 'security', 'update', 'package', 'refund'],
  },
  {
    name: 'Netflix',
    officialRoots: ['netflix'],
    officialDomains: ['netflix.com', 'netflixinvestor.com', 'netflixdnstest0.com'],
    commonKeywords: ['billing', 'update', 'suspend', 'payment', 'renew', 'account'],
  },
  {
    name: 'GitHub',
    officialRoots: ['github'],
    officialDomains: ['github.com', 'github.io', 'githubusercontent.com', 'githubstatus.com'],
    commonKeywords: ['auth', 'repo', 'security', 'token', 'enterprise'],
  },
  {
    name: 'Meta / Facebook',
    officialRoots: ['facebook', 'instagram', 'whatsapp', 'meta'],
    officialDomains: ['facebook.com', 'instagram.com', 'whatsapp.com', 'meta.com', 'fb.com'],
    commonKeywords: ['appeal', 'copyright', 'support', 'business', 'verify', 'security'],
  },
  {
    name: 'Chase',
    officialRoots: ['chase'],
    officialDomains: ['chase.com', 'jpmorganchase.com', 'jpmorgan.com'],
    commonKeywords: ['secure', 'online', 'banking', 'verify', 'card', 'fraud'],
  },
  {
    name: 'Bank of America',
    officialRoots: ['bankofamerica', 'bofa'],
    officialDomains: ['bankofamerica.com', 'bofa.com'],
    commonKeywords: ['online', 'signon', 'banking', 'alert', 'verify'],
  },
  {
    name: 'Wells Fargo',
    officialRoots: ['wellsfargo'],
    officialDomains: ['wellsfargo.com'],
    commonKeywords: ['signon', 'online', 'banking', 'verify', 'alert'],
  },
  {
    name: 'DocuSign',
    officialRoots: ['docusign'],
    officialDomains: ['docusign.com', 'docusign.net'],
    commonKeywords: ['envelope', 'sign', 'document', 'review', 'access'],
  },
  {
    name: 'Dropbox',
    officialRoots: ['dropbox'],
    officialDomains: ['dropbox.com', 'dropboxstatic.com'],
    commonKeywords: ['shared', 'file', 'download', 'login', 'transfer'],
  },
];

// Helper to calculate Levenshtein distance
export function levenshteinDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (a[i - 1] === b[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1];
      } else {
        dp[i][j] = 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
      }
    }
  }

  return dp[m][n];
}

export interface BrandDetectionResult {
  targetBrand: string | null;
  isOfficialBrandDomain: boolean;
  similarityScore: number;
  impersonationType: 'typosquat' | 'subdomain_spoof' | 'tld_switch' | 'combo_squatting' | 'none';
  officialDomain?: string;
  warningNotice?: string;
}

/**
 * Extracts root domain name without subdomains or standard TLD.
 * e.g. "accounts.google.com" -> host: accounts.google.com, rootDomain: google.com, rootName: google
 */
export function extractDomainParts(hostname: string) {
  const cleanHost = hostname.toLowerCase().trim();
  const parts = cleanHost.split('.');

  if (parts.length <= 1) {
    return { host: cleanHost, rootDomain: cleanHost, rootName: cleanHost, tld: '', subdomains: [] };
  }

  // Handle multi-part TLDs like .co.uk, .com.au
  const lastPart = parts[parts.length - 1];
  const secondLast = parts[parts.length - 2];
  let rootDomain = '';
  let rootName = '';
  let tld = '';
  let subdomains: string[] = [];

  if (['co', 'com', 'org', 'net', 'gov', 'edu'].includes(secondLast) && parts.length >= 3) {
    rootDomain = parts.slice(-3).join('.');
    rootName = parts[parts.length - 3];
    tld = `${secondLast}.${lastPart}`;
    subdomains = parts.slice(0, -3);
  } else {
    rootDomain = parts.slice(-2).join('.');
    rootName = parts[parts.length - 2];
    tld = lastPart;
    subdomains = parts.slice(0, -2);
  }

  return { host: cleanHost, rootDomain, rootName, tld, subdomains };
}

export function detectBrandImpersonation(hostname: string): BrandDetectionResult {
  const { host, rootDomain, rootName, tld } = extractDomainParts(hostname);

  // 1. Check if host matches any official brand domain directly or via official subdomain
  for (const brand of KNOWN_BRANDS) {
    for (const officialDomain of brand.officialDomains) {
      if (host === officialDomain || host.endsWith(`.${officialDomain}`)) {
        return {
          targetBrand: brand.name,
          isOfficialBrandDomain: true,
          similarityScore: 100,
          impersonationType: 'none',
          officialDomain,
          warningNotice: `Verified official ${brand.name} domain infrastructure.`,
        };
      }
    }
  }

  // 2. Not official. Now check if it impersonates any brand
  for (const brand of KNOWN_BRANDS) {
    for (const root of brand.officialRoots) {
      // Check 2a: Subdomain spoofing (e.g. paypal.com.attacker.com or paypal.verify-account.biz)
      // The attacker puts the brand name into a subdomain or path-like domain
      if (host.includes(root)) {
        // If it contains the brand keyword in the host, but the root domain is NOT official:
        if (rootName === root && !brand.officialDomains.includes(rootDomain)) {
          // TLD switch attack (e.g. paypal.xyz instead of paypal.com)
          return {
            targetBrand: brand.name,
            isOfficialBrandDomain: false,
            similarityScore: 95,
            impersonationType: 'tld_switch',
            officialDomain: brand.officialDomains[0],
            warningNotice: `TLD Spoofing: Domain uses the exact brand name '${root}' on unauthorized TLD .${tld}. Official domain is ${brand.officialDomains[0]}.`,
          };
        }

        // Subdomain spoof (e.g. paypal.com.billing-portal.top or paypal-auth.top)
        if (host.startsWith(`${root}.`) || host.includes(`.${root}.`) || host.includes(`${root}-`)) {
          return {
            targetBrand: brand.name,
            isOfficialBrandDomain: false,
            similarityScore: 90,
            impersonationType: host.includes(`${root}-`) ? 'combo_squatting' : 'subdomain_spoof',
            officialDomain: brand.officialDomains[0],
            warningNotice: `Impersonation: Target leverages '${brand.name}' keywords to deceptively mimic legitimate ${brand.name} services.`,
          };
        }

        // Check if root name contains brand + keyword (combo-squatting, e.g. "paypal-security" or "paypalsecure")
        if (rootName.includes(root)) {
          return {
            targetBrand: brand.name,
            isOfficialBrandDomain: false,
            similarityScore: 88,
            impersonationType: 'combo_squatting',
            officialDomain: brand.officialDomains[0],
            warningNotice: `Combo-squatting: Root domain '${rootName}' combines '${brand.name}' with deceptive security terms.`,
          };
        }
      }

      // Check 2b: Typosquatting / Levenshtein distance on rootName (e.g. "paypa1", "pypal", "amzon")
      // Only check if length is reasonably close and not too short
      if (root.length >= 4) {
        // Levenshtein distance
        const distance = levenshteinDistance(rootName, root);
        if (distance === 1 || (distance === 2 && root.length >= 7)) {
          return {
            targetBrand: brand.name,
            isOfficialBrandDomain: false,
            similarityScore: Math.round((1 - distance / Math.max(rootName.length, root.length)) * 100),
            impersonationType: 'typosquat',
            officialDomain: brand.officialDomains[0],
            warningNotice: `Typosquatting Alert: '${rootName}' is dangerously similar (edit distance: ${distance}) to genuine brand '${root}'.`,
          };
        }

        // Check character substitutions (1 -> l, 0 -> o, rn -> m, etc.)
        const leetNormalized = rootName
          .replace(/1/g, 'l')
          .replace(/0/g, 'o')
          .replace(/vv/g, 'w')
          .replace(/rn/g, 'm')
          .replace(/5/g, 's');

        if (leetNormalized === root && rootName !== root) {
          return {
            targetBrand: brand.name,
            isOfficialBrandDomain: false,
            similarityScore: 92,
            impersonationType: 'typosquat',
            officialDomain: brand.officialDomains[0],
            warningNotice: `Deceptive Typosquatting: Numerical/character substitution detected ('${rootName}' visually mimics '${root}').`,
          };
        }
      }
    }
  }

  return {
    targetBrand: null,
    isOfficialBrandDomain: false,
    similarityScore: 0,
    impersonationType: 'none',
  };
}
