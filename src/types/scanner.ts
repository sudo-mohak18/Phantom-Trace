/**
 * PhantomTrace - Core Type Definitions
 * Professional Threat Intelligence & Phishing Forensics Platform
 */

export type ThreatVerdict = 'clean' | 'suspicious' | 'malicious';
export type ConfidenceLevel = 'low' | 'medium' | 'high';
export type ImpersonationType = 'typosquat' | 'subdomain_spoof' | 'tld_switch' | 'combo_squatting' | 'none';

export interface AttackStoryStep {
  step: number;
  title: string;
  description: string;
  observedEvidence: string;
  inferredIntent: string;
  type: 'recon' | 'delivery' | 'exploitation' | 'action';
}

export interface Explanations {
  beginner: string;
  technical: string;
  analyst: string;
}

export interface Indicator {
  id: string;
  category: string;
  severity: 'high' | 'medium' | 'low' | 'info';
  title: string;
  detail: string;
  scoreContribution: number;
}

export interface UrlIntelligence {
  domain: string;
  rootDomain: string;
  subdomains: string[];
  tld: string;
  path: string;
  entropyDomain: number;
  entropyPath: number;
  homographDetected: boolean;
  punycode: string | null;
  suspiciousParams: string[];
  isShortener: boolean;
  hasIpHost: boolean;
  rawUrl: string;
}

export interface DomainIntelligence {
  ipAddresses: string[];
  dnsRecords: {
    a: string[];
    mx: string[];
    ns: string[];
    txt: string[];
  };
  asn: string;
  country: string;
  registrar: string;
  createdDate: string;
  ageDays: number;
  ssl: {
    valid: boolean;
    issuer: string;
    subject: string;
    daysRemaining: number;
    hasWildcard: boolean;
  };
}

export interface BrandImpersonation {
  targetBrand: string | null;
  isOfficialBrandDomain: boolean;
  similarityScore: number;
  impersonationType: ImpersonationType;
  officialDomain?: string;
  warningNotice?: string;
}

export interface ReputationCheck {
  source: string;
  status: 'clean' | 'flagged';
  detail: string;
}

export interface SuspiciousForm {
  action: string;
  method: string;
  inputTypes: string[];
  isExternal: boolean;
  flaggedReason: string;
}

export interface SuspiciousScript {
  type: 'inline' | 'external';
  snippet: string;
  lineNumber?: number;
  explanation: string;
  risk: 'high' | 'medium' | 'low';
  decodedPayload?: string;
  suspiciousPattern: string;
}

export interface WebsiteInspection {
  finalUrl: string;
  statusCode: number;
  redirectChain: Array<{ url: string; status: number }>;
  suspiciousForms: SuspiciousForm[];
  suspiciousScripts: SuspiciousScript[];
  hiddenElements: Array<{ tag: string; reason: string }>;
  externalResources: string[];
}

export interface MitreMapping {
  id: string;
  tactic: string;
  technique: string;
}

export interface GraphNode {
  id: string;
  label: string;
  category: 'url' | 'domain' | 'ip' | 'dns' | 'ssl' | 'script' | 'form' | 'threat';
  risk: 'clean' | 'suspicious' | 'malicious';
  detail: string;
  x?: number;
  y?: number;
}

export interface GraphLink {
  source: string;
  target: string;
  label: string;
}

export interface ScanResult {
  id: string;
  targetUrl: string;
  normalizedUrl: string;
  timestamp: string;
  overallScore: number; // 0 (safest) to 100 (critical malicious)
  verdict: ThreatVerdict;
  confidence: ConfidenceLevel;
  category: string;
  attackStory: AttackStoryStep[];
  explanations: Explanations;
  urlIntelligence: UrlIntelligence;
  domainIntelligence: DomainIntelligence;
  brandImpersonation: BrandImpersonation;
  reputation: {
    sourcesChecked: number;
    matches: ReputationCheck[];
  };
  websiteInspection: WebsiteInspection;
  mitreMapping: MitreMapping[];
  indicators: Indicator[];
  recommendedActions: {
    immediate: string[];
    socPlaybook: string[];
    userSafety: string[];
  };
  graphData: {
    nodes: GraphNode[];
    links: GraphLink[];
  };
}

export interface EmailScanResult {
  id: string;
  timestamp: string;
  subject: string;
  claimedSender: {
    name: string;
    email: string;
  };
  authenticatedDomain: string;
  returnPath: string;
  replyTo: string | null;
  replyToMismatch: boolean;
  authentication: {
    spf: { status: 'pass' | 'fail' | 'neutral' | 'none'; detail: string };
    dkim: { status: 'pass' | 'fail' | 'none'; detail: string };
    dmarc: { status: 'pass' | 'fail' | 'none'; detail: string };
  };
  riskScore: number;
  extractedUrls: Array<{
    url: string;
    domain: string;
    isHighRisk: boolean;
    reason?: string;
  }>;
  attachments: Array<{
    filename: string;
    mimeType: string;
    size: string;
    isRisky: boolean;
    riskDetail?: string;
  }>;
  summary: string;
  indicators: string[];
}

export interface ChatMessage {
  id: string;
  sender: 'user' | 'assistant';
  content: string;
  timestamp: string;
  suggestions?: string[];
}
