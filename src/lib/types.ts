// ============ Core Forensics Data Model ============

export interface EmailAddress {
  name: string;
  address: string;
}

export interface EmailMetadata {
  from: string;
  fromName: string;
  fromAddress: string;
  to: string[];
  toAddresses: EmailAddress[];
  cc: string[];
  bcc: string[];
  replyTo: string;
  returnPath: string;
  subject: string;
  date: string;
  messageId: string;
  inReplyTo: string;
  references: string;
  userAgent: string;
  mimeVersion: string;
  contentType: string;
  textBody: string;
  htmlBody: string;
  rawHeaders: Record<string, string>;
}

export interface ReceivedHop {
  raw: string;
  from: string;
  by: string;
  with: string;
  id: string;
  forAddr: string;
  timestamp: string;
  timezone: string;
  sourceIp: string;
  sourceHostname: string;
  protocol: string;
  index: number;
}

export interface HeaderAnomaly {
  type: string;
  description: string;
  severity: "info" | "low" | "medium" | "high";
  evidence: string;
  category: string;
}

export interface AuthResult {
  spf: string;
  dkim: string;
  dmarc: string;
  arc: string;
  spfDomain: string;
  spfRecord: string;
  dkimDomain: string;
  dkimSelector: string;
  dmarcPolicy: string;
  authDetails: string;
}

export interface IPIndicator {
  address: string;
  type: "ipv4" | "ipv6";
  classification: "public" | "private" | "loopback" | "link-local" | "invalid";
  source: string;
  threat: ThreatIntelResult | null;
  geo: GeoLocation | null;
}

export interface DomainIndicator {
  domain: string;
  source: string;
  threat: ThreatIntelResult | null;
}

export interface URLIndicator {
  url: string;
  domain: string;
  source: string;
  threat: ThreatIntelResult | null;
  isPunycode: boolean;
}

export interface HashIndicator {
  fileName: string;
  hashType: "md5" | "sha1" | "sha256";
  hash: string;
  threat: ThreatIntelResult | null;
}

export interface EmailAddrIndicator {
  address: string;
  source: string;
}

export interface Indicators {
  ips: IPIndicator[];
  domains: DomainIndicator[];
  urls: URLIndicator[];
  hashes: HashIndicator[];
  emailAddresses: EmailAddrIndicator[];
  attachments: AttachmentInfo[];
}

export interface AttachmentInfo {
  filename: string;
  mimeType: string;
  size: number;
  sha256: string;
  sha1: string;
  md5: string;
  extension: string;
  isDangerous: boolean;
}

export interface GeoLocation {
  ip: string;
  country: string;
  countryCode: string;
  region: string;
  city: string;
  latitude: number;
  longitude: number;
  isp: string;
  asn: string;
  org: string;
  source: string;
  success: boolean;
}

export interface ThreatIntelResult {
  indicator: string;
  type: "ip" | "domain" | "url" | "hash";
  reputation: "clean" | "suspicious" | "malicious" | "unknown";
  score: number;
  detections: number;
  details: string;
  provider: string;
  available: boolean;
  category: string;
}

export interface RiskFactor {
  name: string;
  points: number;
  evidence: string;
  category: string;
  severity: "info" | "low" | "medium" | "high";
}

export interface RiskAssessment {
  score: number;
  level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  confidence: number;
  factors: RiskFactor[];
}

export interface GraphNode {
  id: string;
  label: string;
  type: string;
  risk?: "high" | "medium" | "low" | "none";
}

export interface GraphEdge {
  source: string;
  target: string;
  label: string;
}

export interface InvestigationGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface AIAssessment {
  available: boolean;
  executiveSummary: string;
  whySuspicious: string;
  keyEvidence: string[];
  attackTechnique: string;
  recommendedActions: string[];
  confidence: string;
  limitations: string;
  provider: string;
}

export interface ReportInfo {
  generatedAt: string;
  format: "json" | "html";
  sections: string[];
}

export interface AnalysisResult {
  investigationId: string;
  filename: string;
  uploadedAt: string;
  analyzedAt: string;
  status: "completed" | "partial" | "failed";
  email: EmailMetadata;
  headers: ReceivedHop[];
  anomalies: HeaderAnomaly[];
  authentication: AuthResult;
  indicators: Indicators;
  threatIntelligence: ThreatIntelResult[];
  geolocation: GeoLocation[];
  risk: RiskAssessment;
  aiAssessment: AIAssessment;
  graph: InvestigationGraph;
  report: ReportInfo;
  errors: string[];
}

export type ProcessingStage =
  | "uploading"
  | "parsing"
  | "header_forensics"
  | "extracting_indicators"
  | "threat_intelligence"
  | "geolocation"
  | "risk_analysis"
  | "ai_analysis"
  | "generating_report"
  | "saving_investigation"
  | "completed";

export interface ProcessingStep {
  stage: ProcessingStage;
  label: string;
  status: "pending" | "active" | "done" | "error";
}
