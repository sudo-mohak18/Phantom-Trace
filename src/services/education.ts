/**
 * PhantomTrace - Cyber Awareness & Security Education Engine
 * Interactive learning modules and "Spot the Phish" forensic quizzes for beginners and professionals.
 */

export interface QuizQuestion {
  id: string;
  scenario: string;
  context: string;
  optionA: {
    label: string;
    detail: string;
    isSuspicious: boolean;
  };
  optionB: {
    label: string;
    detail: string;
    isSuspicious: boolean;
  };
  correctChoice: 'A' | 'B';
  explanation: string;
  threatType: string;
  keyClues: string[];
}

export interface EducationTopic {
  id: string;
  title: string;
  tagline: string;
  category: 'Fundamentals' | 'Detection' | 'Response' | 'Hardening';
  readingTime: string;
  summary: string;
  sections: Array<{
    heading: string;
    content: string;
    proTip?: string;
  }>;
}

export const QUIZ_QUESTIONS: QuizQuestion[] = [
  {
    id: 'quiz-1',
    scenario: 'You received an urgent SMS: "Your PayPal account is restricted. Verify identity now to unfreeze funds."',
    context: 'Look closely at the domain structure, subdomains, and root domain.',
    optionA: {
      label: 'https://paypal.com.verify-billing.top/login',
      detail: 'Root domain is verify-billing.top; "paypal.com" is merely a deceptive subdomain.',
      isSuspicious: true,
    },
    optionB: {
      label: 'https://www.paypal.com/signin/restore',
      detail: 'Root domain is genuinely paypal.com secured by PayPal Inc.',
      isSuspicious: false,
    },
    correctChoice: 'A',
    explanation: 'Option A uses Subdomain Spoofing! Attackers place "paypal.com" at the start of the host, but the actual root domain where your password will be sent is "verify-billing.top". The real PayPal domain is Option B.',
    threatType: 'Subdomain Spoofing & Combo-squatting',
    keyClues: [
      'The true domain is always immediately to the left of the final slash or path.',
      'Check the Top-Level Domain (TLD) - PayPal uses .com, not .top.',
    ],
  },
  {
    id: 'quiz-2',
    scenario: 'An email arrives asking you to review an urgent shared invoice on Google Drive.',
    context: 'Inspect the address bar characters and look for subtle non-Latin homoglyphs.',
    optionA: {
      label: 'https://drive.google.com/file/d/1x9a84/view',
      detail: 'Official Google Drive document preview link.',
      isSuspicious: false,
    },
    optionB: {
      label: 'https://drive.g\u043E\u043Egle.com/file/d/1x9a84/view',
      detail: 'Uses Cyrillic letter "о" (U+043E) instead of standard Latin "o".',
      isSuspicious: true,
    },
    correctChoice: 'B',
    explanation: 'Option B is an IDN Homograph Attack! It looks visually identical, but uses the Cyrillic letter "о" (U+043E). When processed by the browser, it converts into a completely different Punycode server owned by attackers.',
    threatType: 'IDN Homograph Substitution',
    keyClues: [
      'Copy the link into a plain text editor or PhantomTrace to reveal hidden Punycode.',
      'Never click direct login links from unexpected shared file notifications.',
    ],
  },
  {
    id: 'quiz-3',
    scenario: 'Your IT Department sends a mandatory Microsoft 365 password expiration warning.',
    context: 'Evaluate the email sender header and Reply-To destination.',
    optionA: {
      label: 'From: it-support@yourcompany.com | Reply-To: it-support@yourcompany.com',
      detail: 'Aligned domain names matching internal corporate IT identity.',
      isSuspicious: false,
    },
    optionB: {
      label: 'From: "IT Helpdesk" <helpdesk@yourcompany.com> | Reply-To: tickets@helpdesk-azure-cloud.cc',
      detail: 'Sender display name looks corporate, but replies are directed to an external .cc domain.',
      isSuspicious: true,
    },
    correctChoice: 'B',
    explanation: 'Option B demonstrates Reply-To Hijacking! While the From header was spoofed to show your company address, any reply you send goes to "helpdesk-azure-cloud.cc", directly into the cybercriminal\'s hands.',
    threatType: 'Email Header & Reply-To Spoofing',
    keyClues: [
      'Always inspect the actual Reply-To and Return-Path headers, not just the display name.',
      'IT departments will almost never use public cloud top-level domains like .cc for ticket replies.',
    ],
  },
  {
    id: 'quiz-4',
    scenario: 'You are reviewing incoming shipping alerts for an online package delivery.',
    context: 'Identify bare IP addresses versus registered domain names.',
    optionA: {
      label: 'http://194.26.29.112/tracking/package?id=98124',
      detail: 'Raw numeric IP address hosting a tracking status page without SSL.',
      isSuspicious: true,
    },
    optionB: {
      label: 'https://www.ups.com/track?loc=en_US&tracknum=1Z999',
      detail: 'Standard official carrier portal with EV TLS certificate.',
      isSuspicious: false,
    },
    correctChoice: 'A',
    explanation: 'Option A uses a bare IP address (194.26.29.112)! Legitimate delivery companies like UPS, FedEx, or DHL never send links with raw numerical IP addresses; bare IPs are frequently used by attackers to bypass domain registration takedowns.',
    threatType: 'Raw IP Host Delivery',
    keyClues: [
      'Legitimate brands always operate under established branded domain names.',
      'Lack of HTTPS / SSL on package tracking links is an immediate red flag.',
    ],
  },
  {
    id: 'quiz-5',
    scenario: 'A colleague messages you a link to review an urgent quarterly budget report.',
    context: 'Look at URL shorteners and obfuscated redirect chains.',
    optionA: {
      label: 'https://bit.ly/3Qx9A1L_BudgetReport_Q4',
      detail: 'Shortened link concealing the actual destination host.',
      isSuspicious: true,
    },
    optionB: {
      label: 'https://corporate-sharepoint.company.com/sites/finance/q4.xlsx',
      detail: 'Direct link to internal enterprise SharePoint repository.',
      isSuspicious: false,
    },
    correctChoice: 'A',
    explanation: 'Option A uses a generic URL shortener (bit.ly)! Attackers love URL shorteners because they hide the malicious destination from email security gateways and victims. Always expand shortened links in PhantomTrace before opening.',
    threatType: 'Obfuscated URL Redirection',
    keyClues: [
      'Shortened links should never be used for sensitive or financial documents.',
      'Use PhantomTrace to inspect the redirect chain before opening.',
    ],
  },
  {
    id: 'quiz-6',
    scenario: 'You are prompted to download an updated HR benefit enrollment packet.',
    context: 'Check attachment extensions and double extensions.',
    optionA: {
      label: 'Benefit_Enrollment_Guide_2026.pdf',
      detail: 'Standard Portable Document Format file.',
      isSuspicious: false,
    },
    optionB: {
      label: 'Benefit_Enrollment_Guide_2026.pdf.hta',
      detail: 'Double extension ending in .hta (HTML Application executable).',
      isSuspicious: true,
    },
    correctChoice: 'B',
    explanation: 'Option B uses a dangerous Double Extension attack! The file name ends in ".hta", which is a Windows HTML Application that executes arbitrary scripts upon being opened, while trying to fool you with ".pdf" in the title.',
    threatType: 'Malicious Executable Attachment',
    keyClues: [
      'The file type is always determined by the VERY LAST extension after the final dot.',
      'Extensions like .hta, .scr, .exe, .vbs, or .iso are dangerous in email attachments.',
    ],
  },
];

export const EDUCATION_TOPICS: EducationTopic[] = [
  {
    id: 'anatomy-of-phish',
    title: 'Anatomy of a Modern Phishing Link',
    tagline: 'Understand the multi-stage architecture attackers use to bypass security filters.',
    category: 'Fundamentals',
    readingTime: '4 min',
    summary: 'Phishing has evolved far beyond obvious Nigerian prince emails. Modern attacks leverage bulletproof CDN proxies, legitimate cloud providers, dynamic redirectors, and high-fidelity replica portals.',
    sections: [
      {
        heading: '1. The Pretext & Delivery Phase',
        content: 'Attackers create a high-urgency pretext (account suspension, legal notice, overdue tax, cryptographic wallet airdrop) to trigger immediate emotional reaction and prevent critical thinking.',
        proTip: 'Whenever an email insists you must act within 24 hours, slow down. Urgency is the #1 social engineering weapon.',
      },
      {
        heading: '2. The Evasion Gateway',
        content: 'To prevent automated scanning by security vendors, phishing kits employ CAPTCHAs, Cloudflare Turnstile, browser fingerprinting, and IP geofencing that only show the phishing page to real human targets while displaying 404s to security bots.',
      },
      {
        heading: '3. The Credential Harvesting & Exfiltration',
        content: 'Once the victim enters their credentials, modern kits use "Adversary-in-the-Middle" (AitM) proxies to capture both the password and the one-time MFA session cookie, immediately hijacking the session.',
        proTip: 'Hardware security keys (FIDO2 / YubiKey) are immune to AitM phishing because the browser cryptographically verifies the exact domain name.',
      },
    ],
  },
  {
    id: 'typosquat-guide',
    title: 'Detecting Typosquatting & Deceptive Domains',
    tagline: 'Spot character swaps, combo-squatting, and deceptive TLD switches in milliseconds.',
    category: 'Detection',
    readingTime: '5 min',
    summary: 'Attackers register domain names that are visually indistinguishable from legitimate brands or append official-sounding keywords to trick users.',
    sections: [
      {
        heading: 'Combo-squatting vs Typosquatting',
        content: 'Typosquatting changes or omits letters (e.g., "paypa1.com" or "amzon.com"). Combo-squatting keeps the legitimate brand name intact but appends words like "-security", "-login", or "-verify" (e.g., "netflix-billing-support.com").',
        proTip: 'Legitimate companies almost never create separate new domains for login pages. They use subdomains on their primary domain (e.g. login.microsoft.com).',
      },
      {
        heading: 'The Subdomain Illusion',
        content: 'In standard DNS syntax, domain parts are read from right to left before the path. In "paypal.com.account-update.xyz/login", the true domain is "account-update.xyz". Everything to the left is merely a subdomain chosen by the attacker.',
      },
    ],
  },
  {
    id: 'incident-response',
    title: 'Emergency Playbook: What To Do If You Clicked',
    tagline: 'Step-by-step triage guide for victims and SOC analysts within the golden hour.',
    category: 'Response',
    readingTime: '6 min',
    summary: 'A clear, non-panicked checklist to minimize damage when an employee or personal user accidentally enters credentials on a phishing page.',
    sections: [
      {
        heading: 'Immediate Containment (Minutes 0 - 15)',
        content: '1. Immediately navigate to the legitimate service from a different, known-safe device.\n2. Change your password to a strong, unique passphrase.\n3. Terminate all active sessions (sign out of all devices).\n4. In corporate environments, notify your SOC or security team immediately—do not hide the mistake.',
        proTip: 'Early self-reporting prevents an active breach. Security teams respect users who immediately report misclicks.',
      },
      {
        heading: 'Account Hardening (Minutes 15 - 60)',
        content: '1. Review account settings for newly created email forwarding rules, unknown OAuth apps, or altered recovery phone numbers.\n2. If credit card or banking details were entered, call your bank\'s fraud division to freeze or reissue the card.\n3. Run an EDR / anti-malware scan on the affected workstation to ensure no secondary payload was dropped.',
      },
    ],
  },
];
