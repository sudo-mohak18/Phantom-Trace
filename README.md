# PHANTOMTRACE 🛡️

> **"Every suspicious link has a story. Discover it before it's too late."**

PHANTOMTRACE is an enterprise-grade threat intelligence investigation and phishing forensics platform designed for SOC analysts, penetration testers, security researchers, and security-conscious individuals. It combines deep heuristic static analysis, DNS intelligence, Internationalized Domain Name (IDN) homoglyph detection, Shannon entropy profiling, brand impersonation detection, and conversational AI threat triage powered by **Gemini 3.8 Flash**.

---

## 🌟 Key Features

### 1. 🔍 Autonomous URL Investigation Center
- **Shannon Entropy Analysis**: Detects machine-generated randomized domains (DGA) and obfuscated path payloads.
- **IDN Homograph & Punycode Detection**: Identifies Cyrillic, Greek, and Unicode lookalike character substitutions.
- **Brand Impersonation & Typosquatting**: Recognizes combo-squatting, subdomain spoofing, and Levenshtein edit distance attacks while strictly preserving authentic official brand infrastructure (PayPal, Google, Microsoft, Apple, Amazon, etc.).
- **Interactive 5-Step Pipeline**: Visualizes real progress across URL Intelligence, Domain & Infrastructure, Reputation Telemetry, Website & DOM Inspection, and AI Threat Assessment.

### 2. 📖 Attack Story ("What Is This Link Trying To Do?")
- Chronological, evidence-based narrative breaking down the attacker's trajectory:
  1. *Reconnaissance & Brand Impersonation*
  2. *Delivery & Evasive Redirection*
  3. *Credential Harvesting & Phishing Forms*
  4. *Exfiltration & C2 Communications*
- Distinguishes **Observed Facts** from **Inferred Attacker Motives**.

### 3. 🌐 Threat Explorer (Visual Relationship Graph)
- Interactive node-link topology mapping relationships between investigated URLs, Root Domains, Subdomains, Host IPs, DNS Nameservers, SSL Certificates, and Exfiltration Endpoints.
- Search, filter by category (Infrastructure, Network, Code, Threat Intel), and inspect deep forensic telemetry for any node.

### 4. 💻 Malicious Code & DOM Forensics
- Static analysis of HTML forms, hidden input fields, zero-pixel iframes, anti-debugging keyboard traps (`preventDefault` on F12/right-click), and obfuscated `eval(atob(...))` script payloads.
- Switch between **Technical View** (exact line numbers, decoded payloads, mitigation) and **Simple Explanation** (accessible plain language).

### 5. 🤖 AI Threat Analyst (PhantomTrace Intelligence)
- Conversational SOC Analyst powered by Google's **Gemini 3.8 Flash** (`@google/genai`).
- Multi-turn conversation history with full investigation context awareness.
- 12-second timeout resilience with an automated, evidence-grounded heuristic fallback when offline.

### 6. ✉️ Phishing Email Detective
- Upload or paste raw email messages (`.eml` or RFC 822 headers).
- Verifies SPF, DKIM, and DMARC alignment.
- Flags critical **Reply-To Mismatches** (Business Email Compromise).
- Automatically screens attachments for dangerous executable formats (`.hta`, `.scr`, `.vbs`, `.exe`, etc.) and extracts embedded hyperlinks for one-click triage.

### 7. 🎓 Cyber Awareness Mode
- Educational modules on phishing architecture, typosquatting mechanics, and emergency containment playbooks.
- Interactive **Spot the Phish** quiz featuring 6 real-world scenarios with instant forensic explanations.

### 8. 📊 Professional SOC Dashboard & Exportable Reports
- Session metrics, threat severity distributions, and telemetry history.
- Professional report generation with executive summaries, MITRE ATT&CK technique mapping, and printable PDF styling (`window.print()`).
- One-click **JSON Report** and **CSV IOC** export.

---

## 🔒 Security & SSRF Protection

PHANTOMTRACE enforces strict Server-Side Request Forgery (SSRF) controls to prevent abuse:
- Blocks loopback interfaces (`127.0.0.0/8`, `localhost`, `::1`).
- Blocks RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
- Blocks cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`).
- Enforces strict HTTP/HTTPS protocol validation (blocking `file://`, `gopher://`, `ftp://`).
- Never executes untrusted JavaScript in the client browser.

---

## 🛠️ Tech Stack

- **Frontend**: React 19, TypeScript, Tailwind CSS 4, Vite 8, Lucide React
- **Backend**: Node.js, Express, `dns.promises`, `tsx`
- **AI / LLM Engine**: Google Gen AI SDK (`@google/genai`), Model: `gemini-3.8-flash`
- **Testing**: Node.js built-in test runner (`tsx --test`)

---

## 🚀 Quickstart & Local Development

### Prerequisites
- Node.js 20+ installed
- (Optional) `GEMINI_API_KEY` for AI Threat Analyst features (system automatically defaults to intelligent heuristic fallback if not provided).

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-username/phantomtrace.git
cd phantomtrace

# 2. Install dependencies
npm install

# 3. (Optional) Set your Gemini API Key in .env
cp .env.example .env
# Edit .env with your GEMINI_API_KEY="your_api_key_here"

# 4. Start the full-stack development server
npm run dev
```

The application will be live at `http://localhost:3000`.

---

## 📜 Available Scripts

| Script | Command | Description |
|---|---|---|
| `npm run dev` | `tsx server.ts` | Launches the full-stack Express server with Vite middleware on port 3000 |
| `npm run build` | `vite build` | Compiles the client bundle into the `dist/` production folder |
| `npm run test` | `tsx --test src/services/scanner.test.ts` | Runs the automated forensic and mathematical unit tests |
| `npm run lint` | `tsc --noEmit` | Validates TypeScript types across the entire project |
| `npm start` | `tsx server.ts` | Runs the server in production mode |

---

## 🧪 Unit Testing

Run unit tests covering Shannon entropy, homograph detection, brand preservation, SSRF validation, and scan orchestrations:

```bash
npm test
```

---

## ⚖️ License

Distributed under the Apache-2.0 License. Built for ethical security operations and cybersecurity defense education.
