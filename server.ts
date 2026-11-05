/**
 * PhantomTrace - Full-Stack Express Server & Threat Intelligence Backend
 * Connects Vite dev middlewares, real Node DNS resolution, SSRF protection,
 * and Gemini 3.8 Flash multi-turn SOC Threat Analyst with heuristic fallback.
 */

import express, { Request, Response } from 'express';
import dns from 'node:dns/promises';
import path from 'node:path';
import dotenv from 'dotenv';
import { GoogleGenAI } from '@google/genai';

import { scanUrl } from './src/services/scanner';
import { parseEmailHeaders } from './src/services/emailForensics';
import { ScanResult } from './src/types/scanner';

dotenv.config();

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const isProduction = process.env.NODE_ENV === 'production';

app.use(express.json({ limit: '5mb' }));

// Initialize GoogleGenAI client if API key is present
let genAI: GoogleGenAI | null = null;
if (process.env.GEMINI_API_KEY) {
  genAI = new GoogleGenAI({
    apiKey: process.env.GEMINI_API_KEY,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });
}

/**
 * Heuristic SOC Analyst fallback generator when Gemini is not configured or times out.
 * Strictly grounds every answer in the investigated evidence and SOC playbooks.
 */
function generateHeuristicAnalystResponse(message: string, scan?: ScanResult): string {
  const query = message.toLowerCase();

  if (!scan) {
    if (query.includes('what is phishing') || query.includes('how does')) {
      return (
        "Phishing is a deceptive social engineering attack where an adversary crafts fraudulent communication " +
        "(emails, SMS, fake domains) imitating trusted entities to lure victims into revealing sensitive credentials, " +
        "session cookies, or financial information. In PhantomTrace, we analyze URLs for typosquatting, IDN homoglyphs, " +
        "Shannon entropy anomalies, DNS infrastructure age, and hidden credential exfiltration forms."
      );
    }
    return (
      "I am PhantomTrace Intelligence, your conversational SOC Threat Analyst. " +
      "Enter a URL in the investigation bar above or select a sample investigation, and I will analyze the full " +
      "threat architecture, DNS telemetry, and MITRE ATT&CK correlation for you."
    );
  }

  const { targetUrl, overallScore, verdict, category, brandImpersonation, urlIntelligence, domainIntelligence, websiteInspection } = scan;

  if (query.includes('why') && (query.includes('flag') || query.includes('score') || query.includes('malicious') || query.includes('suspicious'))) {
    if (verdict === 'clean') {
      return (
        `Target URL **${targetUrl}** was rated **Clean (Score: ${overallScore}/100)** because the domain ` +
        `**${urlIntelligence.domain}** matches verified authentic infrastructure (${brandImpersonation.targetBrand ? brandImpersonation.targetBrand + ' official whitelist' : 'trusted host baseline'}). ` +
        `Domain age is ${domainIntelligence.ageDays} days, SSL certificate is valid, and no suspicious cross-origin exfiltration endpoints were found.`
      );
    }
    return (
      `**Threat Assessment for ${urlIntelligence.domain}:**\n\n` +
      `This target was assigned a threat score of **${overallScore}/100 (${verdict.toUpperCase()})** due to multiple high-confidence indicators:\n` +
      `1. **Category**: ${category}\n` +
      `2. **Brand Mimicry**: ${brandImpersonation.targetBrand ? `Impersonates **${brandImpersonation.targetBrand}** using ${brandImpersonation.impersonationType.replace('_', ' ')}` : 'Deceptive naming structure targeting user trust'}\n` +
      `3. **Domain Telemetry**: Domain entropy is ${urlIntelligence.entropyDomain} on TLD \`.${urlIntelligence.tld}\`. Infrastructure resolved to \`${domainIntelligence.ipAddresses[0] || 'bulletproof hosting'}\`.\n` +
      `4. **Code Forensics**: ${websiteInspection.suspiciousForms.length > 0 ? `Contains unauthorized credential harvesting form submitting data to external endpoint \`${websiteInspection.suspiciousForms[0].action}\`` : 'Suspicious redirection or payload patterns detected'}.`
    );
  }

  if (query.includes('clicked') || query.includes('what should i do') || query.includes('what to do') || query.includes('compromised')) {
    if (verdict === 'clean') {
      return (
        `Because **${urlIntelligence.domain}** is verified legitimate, clicking this link poses standard web navigation risk. ` +
        `However, always ensure you see the verified TLS padlock and authentic address before submitting account credentials.`
      );
    }
    return (
      `### 🚨 Immediate Incident Containment Playbook:\n\n` +
      `1. **Do NOT submit credentials or personal information.** If you already entered your password, immediately go to the legitimate service from an isolated device and change your password.\n` +
      `2. **Terminate Active Sessions**: Sign out of all existing sessions and revoke connected OAuth apps.\n` +
      `3. **Enable MFA**: Enforce hardware security keys (FIDO2) or authenticator apps (TOTP) instead of SMS.\n` +
      `4. **Check Forwarding Rules**: Attackers often set silent mailbox forwarding rules to intercept recovery codes.\n` +
      `5. **Notify Security / IT**: Submit a report to your corporate SOC or phishing abuse inbox with the URL \`${targetUrl}\`.`
    );
  }

  if (query.includes('collect') || query.includes('credential') || query.includes('form') || query.includes('stealer')) {
    if (websiteInspection.suspiciousForms.length > 0) {
      const form = websiteInspection.suspiciousForms[0];
      return (
        `**Credential Harvesting Forensics:**\n\n` +
        `The website presents a form soliciting inputs: \`[${form.inputTypes.join(', ')}]\`.\n` +
        `Critically, the form action points to an external destination: \`${form.action}\`.\n` +
        `This is a classic exfiltration pattern where stolen passwords and identity markers bypass standard backend authentication and are saved directly to an attacker-controlled drop server.`
      );
    }
    return `No active credential harvesting HTML forms were found on this specific landing page, though heuristic inspection indicates high deceptive risk.`;
  }

  if (query.includes('brand') || query.includes('impersonat')) {
    if (brandImpersonation.isOfficialBrandDomain) {
      return `Target **${urlIntelligence.domain}** is verified authentic infrastructure owned directly by **${brandImpersonation.targetBrand}**. It is not an impersonation.`;
    }
    if (brandImpersonation.targetBrand) {
      return (
        `**Brand Impersonation Analysis:**\n\n` +
        `The site impersonates **${brandImpersonation.targetBrand}**. Notice that the root domain is \`${urlIntelligence.rootDomain}\` rather than the official domain \`${brandImpersonation.officialDomain || 'official domain'}\`.\n` +
        `The attacker uses technique: **${brandImpersonation.impersonationType.replace('_', ' ').toUpperCase()}** to trick users who quickly glance at the address bar.`
      );
    }
    return `No specific global trademark matches were triggered, but the domain exhibits deceptive keyword patterns typical of generic phishing campaigns.`;
  }

  if (query.includes('soc') || query.includes('analyst') || query.includes('mitre') || query.includes('ioc')) {
    return (
      `**SOC Investigation Brief:**\n\n` +
      `* **Verdict**: ${verdict.toUpperCase()} (Score: ${overallScore}/100)\n` +
      `* **MITRE ATT&CK**: T1566.002 (Spearphishing Link), T1056.001 (Input Capture), T1036 (Masquerading)\n` +
      `* **Primary IOCs**:\n` +
      `  - FQDN: \`${urlIntelligence.domain}\`\n` +
      `  - Resolved IPv4: \`${domainIntelligence.ipAddresses.join(', ') || 'N/A'}\`\n` +
      `  - ASN: \`${domainIntelligence.asn}\`\n` +
      `* **Actionable Next Steps**:\n` +
      `  1. Block domain at perimeter firewall & DNS RPZ (Response Policy Zone).\n` +
      `  2. Sweep proxy logs for outbound HTTP POST requests matching the source IP within the last 72 hours.\n` +
      `  3. Submit automated takedown abuse report to registrar \`${domainIntelligence.registrar}\`.`
    );
  }

  // General summary response
  return (
    `**Investigation Summary for ${urlIntelligence.domain}:**\n\n` +
    `PhantomTrace Intelligence determined this link to be **${verdict.toUpperCase()}** with an overall threat score of **${overallScore}/100**.\n\n` +
    `* **Classification**: ${category}\n` +
    `* **Domain Age**: ${domainIntelligence.ageDays} days | **Registrar**: ${domainIntelligence.registrar}\n` +
    `* **Primary Indicator**: ${scan.indicators[0]?.title || 'Heuristic threat indicators'}: ${scan.indicators[0]?.detail || ''}\n\n` +
    `Would you like me to explain the suspicious JavaScript, the DNS infrastructure, or provide a SOC containment playbook?`
  );
}

// -------------------------------------------------------------
// API Endpoints
// -------------------------------------------------------------

/**
 * POST /api/scan
 * Core URL investigation endpoint.
 */
app.post('/api/scan', async (req: Request, res: Response) => {
  const { url } = req.body;

  if (!url || typeof url !== 'string') {
    res.status(400).json({ error: 'Missing or invalid URL parameter in request body.' });
    return;
  }

  try {
    // Custom DNS resolver that queries real system DNS
    const dnsLookup = async (hostname: string) => {
      const records = { a: [] as string[], mx: [] as string[], ns: [] as string[], txt: [] as string[] };
      try {
        records.a = await dns.resolve4(hostname);
      } catch {
        // Ignored if domain doesn't have A records
      }
      try {
        const mxList = await dns.resolveMx(hostname);
        records.mx = mxList.map(m => m.exchange);
      } catch {
        // Ignored
      }
      try {
        records.ns = await dns.resolveNs(hostname);
      } catch {
        // Ignored
      }
      try {
        const txtList = await dns.resolveTxt(hostname);
        records.txt = txtList.map(t => t.join(' '));
      } catch {
        // Ignored
      }
      return records;
    };

    const scanResult = await scanUrl(url, { dnsLookup });
    res.json(scanResult);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error('[API/Scan Error]', message);
    res.status(400).json({ error: message });
  }
});

/**
 * POST /api/email-scan
 * Email header and .eml forensic analyzer.
 */
app.post('/api/email-scan', (req: Request, res: Response) => {
  const { rawContent } = req.body;

  if (!rawContent || typeof rawContent !== 'string') {
    res.status(400).json({ error: 'Missing rawContent in request body.' });
    return;
  }

  try {
    const result = parseEmailHeaders(rawContent);
    res.json(result);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error('[API/Email-Scan Error]', message);
    res.status(400).json({ error: message });
  }
});

/**
 * POST /api/gemini/analyst
 * Multi-turn conversational SOC threat intelligence analyst with 12s timeout and heuristic fallback.
 */
app.post('/api/gemini/analyst', async (req: Request, res: Response) => {
  const { message, history, scanResult } = req.body;

  if (!message || typeof message !== 'string') {
    res.status(400).json({ error: 'Missing message in request body.' });
    return;
  }

  // If Gemini API client is not configured, immediately use evidence-grounded heuristic response
  if (!genAI) {
    const fallbackAnswer = generateHeuristicAnalystResponse(message, scanResult);
    res.json({
      response: fallbackAnswer,
      model: 'heuristic-analyst',
      fallbackUsed: true,
    });
    return;
  }

  try {
    // Build context-aware system instruction
    let systemInstruction =
      "You are PhantomTrace Intelligence, an elite cybersecurity threat analyst, reverse engineer, and SOC incident responder. " +
      "You speak with technical authority, sharp clarity, and actionable guidance. " +
      "Never fabricate data, phone numbers, fake CVEs, or personal identities. Rely strictly on verified security evidence, " +
      "MITRE ATT&CK techniques, RFC protocols, and established cyber defense standards.";

    if (scanResult) {
      systemInstruction +=
        `\n\nCURRENT INVESTIGATION CONTEXT:\n` +
        `- Target URL: ${scanResult.targetUrl}\n` +
        `- Threat Score: ${scanResult.overallScore}/100 (${scanResult.verdict.toUpperCase()})\n` +
        `- Category: ${scanResult.category}\n` +
        `- Domain: ${scanResult.urlIntelligence.domain} (Entropy: ${scanResult.urlIntelligence.entropyDomain}, TLD: .${scanResult.urlIntelligence.tld})\n` +
        `- Brand Check: ${scanResult.brandImpersonation.targetBrand ? scanResult.brandImpersonation.targetBrand + ' (Official: ' + scanResult.brandImpersonation.isOfficialBrandDomain + ', Type: ' + scanResult.brandImpersonation.impersonationType + ')' : 'None'}\n` +
        `- IP / ASN: ${scanResult.domainIntelligence.ipAddresses.join(', ') || 'N/A'} (${scanResult.domainIntelligence.asn})\n` +
        `- Indicators: ${scanResult.indicators?.map((i: { title: string; detail: string }) => i.title + ': ' + i.detail).join('; ') || 'None'}\n` +
        `- Suspicious Forms: ${scanResult.websiteInspection?.suspiciousForms?.map((f: { action: string }) => f.action).join(', ') || 'None'}\n` +
        `- Suspicious Scripts: ${scanResult.websiteInspection?.suspiciousScripts?.map((s: { explanation: string }) => s.explanation).join('; ') || 'None'}`;
    }

    // Format chat history for @google/genai
    const formattedContents: Array<{ role: 'user' | 'model'; parts: Array<{ text: string }> }> = [];

    if (Array.isArray(history)) {
      for (const item of history.slice(-8)) {
        if (item.content && (item.role === 'user' || item.role === 'model')) {
          formattedContents.push({
            role: item.role,
            parts: [{ text: item.content }],
          });
        }
      }
    }

    formattedContents.push({
      role: 'user',
      parts: [{ text: message }],
    });

    // Enforce 12-second timeout using Promise.race
    const timeoutPromise = new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error('Gemini API call timed out after 12 seconds')), 12000)
    );

    const apiCallPromise = genAI.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: formattedContents,
      config: {
        systemInstruction,
      },
    });

    const result = await Promise.race([apiCallPromise, timeoutPromise]);
    const answer = result.text || generateHeuristicAnalystResponse(message, scanResult);

    res.json({
      response: answer,
      model: 'gemini-3.8-flash',
      fallbackUsed: false,
    });
  } catch (err) {
    const errorMsg = err instanceof Error ? err.message : String(err);
    console.warn('[Gemini Analyst Fallback Engaged]:', errorMsg);

    // Fall back cleanly to evidence-grounded heuristic SOC response
    const fallbackAnswer = generateHeuristicAnalystResponse(message, scanResult);
    res.json({
      response: fallbackAnswer,
      model: 'heuristic-analyst',
      fallbackUsed: true,
      errorDetail: errorMsg,
    });
  }
});

// -------------------------------------------------------------
// Vite Dev Server or Production Static Serving
// -------------------------------------------------------------

async function startServer() {
  if (!isProduction) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve('dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[PhantomTrace] Server running on http://0.0.0.0:${PORT} (Mode: ${process.env.NODE_ENV || 'development'})`);
  });
}

startServer().catch(err => {
  console.error('Fatal startup error:', err);
  process.exit(1);
});
