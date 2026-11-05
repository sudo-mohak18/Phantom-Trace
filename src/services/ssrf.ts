/**
 * Server-Side Request Forgery (SSRF) Protection Engine
 * Blocks internal infrastructure, loopback, private IP ranges, cloud metadata services, and unsafe schemes.
 */

export interface SsrfValidationResult {
  isSafe: boolean;
  blockedReason?: string;
}

export function isPrivateIp(ip: string): boolean {
  // IPv4 checks
  const ipv4Match = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4Match) {
    const octets = ipv4Match.slice(1, 5).map(Number);
    if (octets.some(o => o > 255)) return true; // Malformed IP

    const [a, b] = octets;

    // 0.0.0.0/8 (Broadcast/Current network)
    if (a === 0) return true;

    // 127.0.0.0/8 (Loopback)
    if (a === 127) return true;

    // 10.0.0.0/8 (RFC 1918 Private)
    if (a === 10) return true;

    // 172.16.0.0/12 (RFC 1918 Private)
    if (a === 172 && b >= 16 && b <= 31) return true;

    // 192.168.0.0/16 (RFC 1918 Private)
    if (a === 192 && b === 168) return true;

    // 169.254.0.0/16 (Link-Local & Cloud Metadata, e.g. 169.254.169.254)
    if (a === 169 && b === 254) return true;

    // 100.64.0.0/10 (Carrier-grade NAT)
    if (a === 100 && b >= 64 && b <= 127) return true;

    // 224.0.0.0/4 (Multicast)
    if (a >= 224) return true;

    return false;
  }

  // IPv6 checks
  const lower = ip.toLowerCase();
  if (lower === '::1' || lower === '::' || lower.startsWith('fe80:') || lower.startsWith('fc') || lower.startsWith('fd')) {
    return true; // Loopback, link-local, or unique local
  }

  return false;
}

export function validateUrlForSsrf(targetUrl: string): SsrfValidationResult {
  if (!targetUrl || typeof targetUrl !== 'string') {
    return { isSafe: false, blockedReason: 'Empty or invalid URL provided.' };
  }

  let parsed: URL;
  try {
    parsed = new URL(targetUrl.trim());
  } catch {
    return { isSafe: false, blockedReason: 'Malformed URL: Could not be parsed.' };
  }

  // 1. Enforce allowed schemes only (http, https)
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return {
      isSafe: false,
      blockedReason: `Blocked protocol '${parsed.protocol}'. Only http and https are permitted.`,
    };
  }

  const hostname = parsed.hostname.toLowerCase();

  // 2. Block localhost and local names
  if (
    hostname === 'localhost' ||
    hostname === '127.0.0.1' ||
    hostname === '0.0.0.0' ||
    hostname === '::1' ||
    hostname.endsWith('.localhost') ||
    hostname.endsWith('.local') ||
    hostname.endsWith('.internal') ||
    hostname.endsWith('.lan') ||
    hostname.endsWith('.corp') ||
    hostname.endsWith('.home') ||
    hostname.includes('metadata.google.internal') ||
    hostname.includes('instance-data')
  ) {
    return {
      isSafe: false,
      blockedReason: `Security policy blocks scanning internal/localhost/cloud metadata target: ${hostname}`,
    };
  }

  // 3. Direct IP checking
  if (isPrivateIp(hostname)) {
    return {
      isSafe: false,
      blockedReason: `Security policy blocks scanning private or non-routable IP address: ${hostname}`,
    };
  }

  return { isSafe: true };
}
