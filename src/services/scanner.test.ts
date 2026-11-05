/**
 * Fast-Feedback Unit Tests for PhantomTrace Forensics & Scanner Logic
 * Runs via Node's built-in test runner: tsx --test src/services/scanner.test.ts
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { calculateShannonEntropy } from './entropy';
import { detectHomographAttack } from './homograph';
import { detectBrandImpersonation } from './brands';
import { validateUrlForSsrf, isPrivateIp } from './ssrf';
import { scanUrl } from './scanner';

test('Entropy Calculation: handles empty, static, and high-entropy strings', () => {
  assert.equal(calculateShannonEntropy(''), 0);
  assert.equal(calculateShannonEntropy('aaaaaaa'), 0);
  // Mixed character domain should have moderate entropy
  const entropy = calculateShannonEntropy('google.com');
  assert.ok(entropy > 2.0 && entropy < 3.5, `Expected moderate entropy, got ${entropy}`);

  // Random DGA-like string should have high entropy
  const highEntropy = calculateShannonEntropy('x98zqk2m4p901af7');
  assert.ok(highEntropy > 3.5, `Expected high entropy, got ${highEntropy}`);
});

test('Homograph Detection: flags Cyrillic homoglyphs and punycode', () => {
  // Pure ASCII paypal
  const clean = detectHomographAttack('paypal.com');
  assert.equal(clean.detected, false);

  // Cyrillic 'а' (U+0430) replacing Latin 'a'
  const spoofed = detectHomographAttack('\u0430pple.com');
  assert.equal(spoofed.detected, true);
  assert.ok(spoofed.replacedCharacters.length > 0);

  // Punycode representation
  const punycode = detectHomographAttack('xn--pple-43d.com');
  assert.equal(punycode.detected, true);
  assert.equal(punycode.isPunycode, true);
});

test('Brand Impersonation: strictly preserves official domains as clean', () => {
  // Official brand domains across different official TLDs and subdomains
  const officialPayPal = detectBrandImpersonation('paypal.com');
  assert.equal(officialPayPal.isOfficialBrandDomain, true);
  assert.equal(officialPayPal.impersonationType, 'none');

  const officialGoogleAccounts = detectBrandImpersonation('accounts.google.com');
  assert.equal(officialGoogleAccounts.isOfficialBrandDomain, true);
  assert.equal(officialGoogleAccounts.impersonationType, 'none');

  const officialMicrosoft = detectBrandImpersonation('login.microsoft.com');
  assert.equal(officialMicrosoft.isOfficialBrandDomain, true);
  assert.equal(officialMicrosoft.impersonationType, 'none');

  const officialApple = detectBrandImpersonation('appleid.apple.com');
  assert.equal(officialApple.isOfficialBrandDomain, true);
  assert.equal(officialApple.impersonationType, 'none');

  const officialAmazon = detectBrandImpersonation('amazon.co.uk');
  assert.equal(officialAmazon.isOfficialBrandDomain, true);
  assert.equal(officialAmazon.impersonationType, 'none');
});

test('Brand Impersonation: catches typosquats, combo-squats and subdomain spoofs', () => {
  // Typosquat with number substitution
  const typosquat = detectBrandImpersonation('paypa1.com');
  assert.equal(typosquat.isOfficialBrandDomain, false);
  assert.equal(typosquat.targetBrand, 'PayPal');
  assert.equal(typosquat.impersonationType, 'typosquat');

  // Combo-squatting
  const combo = detectBrandImpersonation('paypal-security-account.top');
  assert.equal(combo.isOfficialBrandDomain, false);
  assert.equal(combo.targetBrand, 'PayPal');
  assert.ok(combo.impersonationType === 'combo_squatting' || combo.impersonationType === 'subdomain_spoof');

  // Subdomain spoofing
  const subSpoof = detectBrandImpersonation('paypal.com.attacker-controlled.net');
  assert.equal(subSpoof.isOfficialBrandDomain, false);
  assert.equal(subSpoof.targetBrand, 'PayPal');
  assert.equal(subSpoof.impersonationType, 'subdomain_spoof');
});

test('SSRF Protection: blocks private IPs, loopback, and cloud metadata', () => {
  // Loopback
  assert.equal(isPrivateIp('127.0.0.1'), true);
  assert.equal(isPrivateIp('127.0.1.10'), true);
  assert.equal(isPrivateIp('::1'), true);

  // Private RFC 1918
  assert.equal(isPrivateIp('10.0.0.1'), true);
  assert.equal(isPrivateIp('172.16.0.1'), true);
  assert.equal(isPrivateIp('172.31.255.255'), true);
  assert.equal(isPrivateIp('192.168.1.254'), true);

  // Cloud metadata IP
  assert.equal(isPrivateIp('169.254.169.254'), true);

  // Public IP
  assert.equal(isPrivateIp('8.8.8.8'), false);
  assert.equal(isPrivateIp('142.250.190.46'), false);

  // URL checking
  assert.equal(validateUrlForSsrf('http://localhost:3000').isSafe, false);
  assert.equal(validateUrlForSsrf('http://127.0.0.1/admin').isSafe, false);
  assert.equal(validateUrlForSsrf('http://169.254.169.254/latest/meta-data').isSafe, false);
  assert.equal(validateUrlForSsrf('http://10.20.30.40/api').isSafe, false);
  assert.equal(validateUrlForSsrf('file:///etc/passwd').isSafe, false);
  assert.equal(validateUrlForSsrf('https://paypal.com').isSafe, true);
});

test('Scan Orchestrator: official brand gets clean verdict while phish gets malicious', async () => {
  // Scan official domain
  const cleanResult = await scanUrl('https://paypal.com');
  assert.equal(cleanResult.verdict, 'clean');
  assert.ok(cleanResult.overallScore <= 4);
  assert.equal(cleanResult.brandImpersonation.isOfficialBrandDomain, true);

  // Scan combo-squatting malicious target
  const phishResult = await scanUrl('https://paypal-security-account.support/verify/auth.php');
  assert.equal(phishResult.verdict, 'malicious');
  assert.ok(phishResult.overallScore >= 65);
  assert.ok(phishResult.attackStory.length >= 3);
  assert.ok(phishResult.indicators.length >= 2);
});
