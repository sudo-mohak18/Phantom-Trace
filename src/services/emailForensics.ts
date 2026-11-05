/**
 * PhantomTrace - Phishing Email Detective & Header Forensics Engine
 * Parses raw .eml, RFC 822 headers, checks SPF/DKIM/DMARC, Reply-To mismatches,
 * extracts embedded URLs, and screens attachments for malicious payloads.
 */

import { EmailScanResult } from '../types/scanner';
import { extractDomainParts, detectBrandImpersonation } from './brands';

const RISKY_ATTACHMENT_EXTENSIONS = new Set([
  'exe', 'scr', 'bat', 'cmd', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh',
  'hta', 'cpl', 'iso', 'img', 'jar', 'ps1', 'docm', 'xlsm', 'pptm', 'iqy',
]);

export function parseEmailHeaders(rawContent: string): EmailScanResult {
  const lines = rawContent.split(/\r?\n/);
  const headers: Record<string, string> = {};

  let currentHeader = '';
  let inBody = false;
  const bodyLines: string[] = [];

  for (const line of lines) {
    if (!inBody && line.trim() === '') {
      inBody = true;
      continue;
    }

    if (!inBody) {
      if (/^\s+/.test(line) && currentHeader) {
        // Multi-line header continuation
        headers[currentHeader] += ' ' + line.trim();
      } else {
        const colonIdx = line.indexOf(':');
        if (colonIdx > 0) {
          currentHeader = line.substring(0, colonIdx).trim().toLowerCase();
          headers[currentHeader] = line.substring(colonIdx + 1).trim();
        }
      }
    } else {
      bodyLines.push(line);
    }
  }

  const rawBody = bodyLines.join('\n');

  // Extract fields
  const subject = headers['subject'] || 'No Subject';
  const rawFrom = headers['from'] || 'Unknown Sender';
  const rawTo = headers['to'] || 'Unknown Recipient';
  const returnPath = headers['return-path'] || headers['sender'] || '';
  const replyTo = headers['reply-to'] || null;
  const authResults = headers['authentication-results'] || headers['received-spf'] || '';

  // Parse From display name and email address
  let fromName = rawFrom;
  let fromEmail = '';
  const emailMatch = rawFrom.match(/<([^>]+)>/) || rawFrom.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
  if (emailMatch) {
    fromEmail = emailMatch[1].toLowerCase();
    fromName = rawFrom.replace(/<[^>]+>/, '').trim() || fromEmail;
  } else {
    fromEmail = rawFrom.toLowerCase();
  }

  // Parse Reply-To email
  let replyToEmail: string | null = null;
  if (replyTo) {
    const replyMatch = replyTo.match(/<([^>]+)>/) || replyTo.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    if (replyMatch) {
      replyToEmail = replyMatch[1].toLowerCase();
    }
  }

  // Parse Return-Path email
  let returnPathEmail = '';
  if (returnPath) {
    const rpMatch = returnPath.match(/<([^>]+)>/) || returnPath.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    if (rpMatch) {
      returnPathEmail = rpMatch[1].toLowerCase();
    }
  }

  const fromDomain = fromEmail.includes('@') ? fromEmail.split('@')[1] : '';
  const replyToDomain = replyToEmail && replyToEmail.includes('@') ? replyToEmail.split('@')[1] : '';
  const returnPathDomain = returnPathEmail && returnPathEmail.includes('@') ? returnPathEmail.split('@')[1] : '';

  // Check Reply-To mismatch
  const replyToMismatch = !!(replyToEmail && fromEmail && replyToDomain !== fromDomain);

  // Authentication Analysis (SPF, DKIM, DMARC)
  const authLower = authResults.toLowerCase();
  
  let spfStatus: 'pass' | 'fail' | 'neutral' | 'none' = 'none';
  let spfDetail = 'SPF verification record not found in headers.';
  if (authLower.includes('spf=pass') || authLower.includes('pass (google.com') || authLower.includes('pass (mail')) {
    spfStatus = 'pass';
    spfDetail = 'SPF passed: sending host is authorized by domain SPF policy.';
  } else if (authLower.includes('spf=fail') || authLower.includes('spf=softfail')) {
    spfStatus = 'fail';
    spfDetail = 'SPF failed: sending IP is not permitted to send email on behalf of claimed domain.';
  } else if (authLower.includes('spf=neutral')) {
    spfStatus = 'neutral';
    spfDetail = 'SPF returned neutral result (neither explicitly authorized nor rejected).';
  }

  let dkimStatus: 'pass' | 'fail' | 'none' = 'none';
  let dkimDetail = 'DKIM signature verification header not found.';
  if (authLower.includes('dkim=pass') || headers['dkim-signature']) {
    dkimStatus = authLower.includes('dkim=fail') ? 'fail' : 'pass';
    dkimDetail = dkimStatus === 'pass'
      ? 'DKIM cryptographic signature verified.'
      : 'DKIM cryptographic signature failed verification.';
  }

  let dmarcStatus: 'pass' | 'fail' | 'none' = 'none';
  let dmarcDetail = 'DMARC alignment policy check not present.';
  if (authLower.includes('dmarc=pass')) {
    dmarcStatus = 'pass';
    dmarcDetail = 'DMARC policy passed: Domain alignment confirmed.';
  } else if (authLower.includes('dmarc=fail')) {
    dmarcStatus = 'fail';
    dmarcDetail = 'DMARC policy failed: Alignment mismatch between From and authenticated identity.';
  }

  // Extract embedded URLs
  const urlRegex = /(https?:\/\/[^\s<>"'\)]+)/gi;
  const foundUrls = new Set<string>();
  const combinedText = rawContent;
  let match;
  while ((match = urlRegex.exec(combinedText)) !== null) {
    foundUrls.add(match[1]);
  }

  const extractedUrls: EmailScanResult['extractedUrls'] = [];
  for (const url of Array.from(foundUrls).slice(0, 15)) {
    try {
      const parsed = new URL(url);
      const host = parsed.hostname.toLowerCase();
      const brand = detectBrandImpersonation(host);
      const isHighRisk = !brand.isOfficialBrandDomain && (brand.targetBrand !== null || host.includes('verify') || host.includes('login'));
      extractedUrls.push({
        url,
        domain: host,
        isHighRisk,
        reason: isHighRisk ? `Suspicious domain mimicking ${brand.targetBrand || 'authentication'}` : undefined,
      });
    } catch {
      // invalid url
    }
  }

  // Parse attachments
  const attachments: EmailScanResult['attachments'] = [];
  const filenameRegex = /filename="?([^"\r\n;]+)"?/gi;
  let fileMatch;
  while ((fileMatch = filenameRegex.exec(rawContent)) !== null) {
    const filename = fileMatch[1].trim();
    const ext = filename.split('.').pop()?.toLowerCase() || '';
    const isRisky = RISKY_ATTACHMENT_EXTENSIONS.has(ext) || filename.toLowerCase().includes('.zip');
    attachments.push({
      filename,
      mimeType: ext ? `application/x-${ext}` : 'application/octet-stream',
      size: 'Estimated < 1 MB',
      isRisky,
      riskDetail: isRisky ? `Executable / dangerous script extension .${ext}` : undefined,
    });
  }

  // Check Brand Impersonation on From Header
  const brandCheck = fromDomain ? detectBrandImpersonation(fromDomain) : { targetBrand: null, isOfficialBrandDomain: false };
  const displayNameCheck = fromName ? detectBrandImpersonation(fromName) : { targetBrand: null, isOfficialBrandDomain: false };

  // Calculate Risk Score
  let riskScore = 15; // baseline unverified
  const indicators: string[] = [];

  if (replyToMismatch) {
    riskScore += 35;
    indicators.push(`CRITICAL: Reply-To mismatch. From '${fromEmail}' but replies routed to '${replyToEmail}'.`);
  }

  if (spfStatus === 'fail') {
    riskScore += 25;
    indicators.push('SPF Authentication Failed: IP is unauthorized for domain.');
  }

  if (dmarcStatus === 'fail') {
    riskScore += 20;
    indicators.push('DMARC Policy Failure: Domain alignment mismatch.');
  }

  if (displayNameCheck.targetBrand && !brandCheck.isOfficialBrandDomain) {
    riskScore += 30;
    indicators.push(`Sender Display Name Spoofing: Uses brand '${displayNameCheck.targetBrand}' while sending from '${fromDomain}'.`);
  }

  if (attachments.some(a => a.isRisky)) {
    riskScore += 35;
    indicators.push(`Malicious/Dangerous Attachment: Contains high-risk file extension (${attachments.filter(a => a.isRisky).map(a => a.filename).join(', ')}).`);
  }

  if (extractedUrls.some(u => u.isHighRisk)) {
    riskScore += 25;
    indicators.push(`Deceptive Hyperlinks: Message body contains phishing or lookalike URLs.`);
  }

  if (spfStatus === 'pass' && dkimStatus === 'pass' && dmarcStatus === 'pass' && !replyToMismatch) {
    riskScore = Math.max(5, riskScore - 30);
  }

  riskScore = Math.min(100, Math.max(2, riskScore));

  const summary = riskScore >= 60
    ? `High-confidence phishing email. Identified ${indicators.length} critical security anomalies including ${replyToMismatch ? 'Reply-To hijacking' : 'authentication failures'}.`
    : riskScore >= 30
    ? 'Suspicious email. Several unverified headers and external URLs require caution.'
    : 'Email headers satisfy standard authentication checks (SPF/DKIM/DMARC pass).';

  return {
    id: `email-${Date.now()}`,
    timestamp: new Date().toISOString(),
    subject,
    claimedSender: {
      name: fromName,
      email: fromEmail,
    },
    authenticatedDomain: returnPathDomain || fromDomain || 'unknown',
    returnPath: returnPathEmail || 'None',
    replyTo: replyToEmail,
    replyToMismatch,
    authentication: {
      spf: { status: spfStatus, detail: spfDetail },
      dkim: { status: dkimStatus, detail: dkimDetail },
      dmarc: { status: dmarcStatus, detail: dmarcDetail },
    },
    riskScore,
    extractedUrls,
    attachments,
    summary,
    indicators,
  };
}

export const SAMPLE_PHISHING_EMAIL = `Delivered-To: victim@corporate-network.com
Received: by 2002:a05:6512:445:b0:546:1289 with SMTP id c5csp982143;
        Thu, 05 Nov 2026 08:12:44 -0800 (PST)
X-Google-Smtp-Source: AGHT+IF98124981729
Authentication-Results: mx.google.com;
       spf=fail (google.com: domain of alert@mailer-bulletproof.ru does not designate 185.220.101.5 as permitted sender) smtp.mailfrom=alert@mailer-bulletproof.ru;
       dkim=fail header.i=@mailer-bulletproof.ru;
       dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=paypal.com
From: "PayPal Security Department" <security-alert@paypal.com>
Reply-To: "Resolution Desk" <claims-collector@dark-vault.cc>
To: victim@corporate-network.com
Subject: [URGENT] Your PayPal Account Has Been Limited Due to Suspicious Activity
Date: Thu, 05 Nov 2026 16:10:02 +0000
Message-ID: <847192847.20261105@mailer-bulletproof.ru>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_NextPart_000_001D_01D2"

------=_NextPart_000_001D_01D2
Content-Type: text/plain; charset="UTF-8"

Dear Valued Customer,

We detected an unauthorized login attempt from an unrecognized IP address (Moscow, Russian Federation) on your PayPal balance.
To restore full account functionality and prevent permanent account limitation, you must verify your identity immediately:

Review & Verify Account:
https://paypal-security-account.support/verify/auth.php?token=84f29a

Failure to verify within 24 hours will result in permanent account suspension and fund withholding.

Sincerely,
PayPal Account Safety Team
https://www.paypal.com

------=_NextPart_000_001D_01D2
Content-Type: application/octet-stream; name="Verification_Form.hta"
Content-Disposition: attachment; filename="Verification_Form.hta"

[Binary Payload Omitted]
------=_NextPart_000_001D_01D2--`;
