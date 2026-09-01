// AI Analyzer — structured forensic reasoning, works with or without an LLM
import type { AIAssessment, RiskAssessment, EmailMetadata, AuthResult, Indicators, ThreatIntelResult, HeaderAnomaly } from "./types";

interface AIContext {
  metadata: EmailMetadata;
  authentication: AuthResult;
  indicators: Indicators;
  threatResults: ThreatIntelResult[];
  anomalies: HeaderAnomaly[];
  risk: RiskAssessment;
}

export function generateAIAssessment(ctx: AIContext): AIAssessment {
  const { metadata, authentication, indicators, threatResults, anomalies, risk } = ctx;

  // If Gemini API key is available, try to use it
  // For now, use the deterministic rule-based reasoning engine
  // This generates a structured forensic narrative from the evidence

  const findings: string[] = [];
  const keyEvidence: string[] = [];
  const recommendations: string[] = [];

  // Authentication analysis
  if (authentication.spf === "FAIL" || authentication.spf === "SOFTFAIL") {
    findings.push("SPF authentication check failed, indicating the sending server was not authorized to send email on behalf of the claimed domain.");
    keyEvidence.push(`SPF: ${authentication.spf} for domain ${authentication.spfDomain || "unknown"}`);
  }
  if (authentication.dkim === "FAIL") {
    findings.push("DKIM signature verification failed, suggesting the email content may have been tampered with or the signature is forged.");
    keyEvidence.push(`DKIM: ${authentication.dkim} for domain ${authentication.dkimDomain || "unknown"}`);
  }
  if (authentication.dmarc === "FAIL" || authentication.dmarc === "NONE") {
    findings.push(authentication.dmarc === "FAIL"
      ? "DMARC policy check failed, confirming the email did not pass domain-based authentication."
      : "No DMARC policy was found for the sending domain, which reduces the ability to verify sender legitimacy.");
    keyEvidence.push(`DMARC: ${authentication.dmarc}`);
  }

  // Sender spoofing indicators
  const replyToMismatch = anomalies.find((a) => a.type === "reply_to_mismatch");
  if (replyToMismatch) {
    findings.push("The Reply-To address uses a different domain than the From address, a classic phishing technique to redirect responses to an attacker-controlled address.");
    keyEvidence.push(replyToMismatch.evidence);
  }

  const displaySpoofing = anomalies.find((a) => a.type === "display_name_spoofing");
  if (displaySpoofing) {
    findings.push("The sender's display name impersonates a recognized brand while using a free email provider, indicating brand impersonation.");
    keyEvidence.push(displaySpoofing.evidence);
  }

  // Threat intelligence findings
  const maliciousIPs = threatResults.filter((t) => t.type === "ip" && t.reputation === "malicious");
  const suspiciousIPs = threatResults.filter((t) => t.type === "ip" && t.reputation === "suspicious");
  const maliciousDomains = threatResults.filter((t) => t.type === "domain" && t.reputation === "malicious");
  const maliciousURLs = threatResults.filter((t) => t.type === "url" && t.reputation === "malicious");
  const maliciousHashes = threatResults.filter((t) => t.type === "hash" && t.reputation === "malicious");

  if (maliciousIPs.length > 0) {
    findings.push(`${maliciousIPs.length} IP address(es) in the email's routing path matched known malicious infrastructure in threat intelligence databases.`);
    keyEvidence.push(`Malicious IPs: ${maliciousIPs.map((t) => t.indicator).join(", ")}`);
  } else if (suspiciousIPs.length > 0) {
    findings.push(`${suspiciousIPs.length} IP address(es) showed suspicious reputation characteristics.`);
    keyEvidence.push(`Suspicious IPs: ${suspiciousIPs.map((t) => t.indicator).join(", ")}`);
  }

  if (maliciousDomains.length > 0) {
    findings.push(`${maliciousDomains.length} domain(s) referenced in the email are flagged as malicious.`);
    keyEvidence.push(`Malicious domains: ${maliciousDomains.map((t) => t.indicator).join(", ")}`);
  }

  if (maliciousURLs.length > 0) {
    findings.push(`${maliciousURLs.length} URL(s) in the email body are flagged as malicious by threat intelligence sources.`);
    keyEvidence.push(`Malicious URLs: ${maliciousURLs.map((t) => t.indicator.slice(0, 80)).join(", ")}`);
  }

  if (maliciousHashes.length > 0) {
    findings.push(`${maliciousHashes.length} attachment hash(es) match known malware signatures.`);
    keyEvidence.push(`Malicious hashes detected in attachments`);
  }

  // Dangerous attachments
  const dangerousAtts = indicators.attachments.filter((a) => a.isDangerous);
  if (dangerousAtts.length > 0) {
    findings.push(`The email contains ${dangerousAtts.length} attachment(s) with potentially dangerous file types (${dangerousAtts.map((a) => a.extension).join(", ")}).`);
    keyEvidence.push(`Dangerous attachments: ${dangerousAtts.map((a) => a.filename).join(", ")}`);
  }

  // Suspicious language
  if (risk.factors.some((f) => f.category === "suspicious_language")) {
    findings.push("The subject line contains language consistent with social engineering tactics, creating false urgency or requesting sensitive actions.");
  }

  // If no findings, email appears benign
  if (findings.length === 0) {
    findings.push("No significant malicious indicators were detected. The email passed authentication checks, no known malicious indicators were found, and no suspicious patterns were identified.");
  }

  // Build executive summary
  const executiveSummary = buildExecutiveSummary(risk, authentication, findings);

  // Attack technique interpretation
  const attackTechnique = interpretAttackTechnique(ctx);

  // Recommendations
  if (risk.level === "CRITICAL" || risk.level === "HIGH") {
    recommendations.push("Do not click any links or open attachments in this email.");
    recommendations.push("Quarantine the email and remove it from user inboxes if in a production environment.");
    recommendations.push("Block the identified malicious IP addresses, domains, and URLs at the firewall/email gateway.");
    recommendations.push("Conduct a thorough investigation of the sender and associated infrastructure.");
    recommendations.push("Report this email to your security team and relevant authorities.");
  } else if (risk.level === "MEDIUM") {
    recommendations.push("Exercise caution with this email — verify the sender through an out-of-band channel before taking any action.");
    recommendations.push("Do not click links or download attachments without verifying their safety.");
    recommendations.push("Monitor the sender domain and associated IPs for future malicious activity.");
  } else {
    recommendations.push("The email appears to be low risk, but standard security awareness practices still apply.");
    recommendations.push("No immediate action is required based on the current analysis.");
  }

  recommendations.push("All findings should be validated by a qualified security analyst before taking irreversible action.");
  recommendations.push("This AI assessment is assistive and should not be the sole basis for security decisions.");

  return {
    available: true,
    executiveSummary,
    whySuspicious: findings.join(" "),
    keyEvidence,
    attackTechnique,
    recommendedActions: recommendations,
    confidence: `Assessment confidence: ${Math.round(risk.confidence * 100)}% — based on ${risk.factors.length} risk factors, authentication results, and threat intelligence data.`,
    limitations: "IP geolocation is approximate and does not identify exact physical locations. Email headers can be spoofed. Threat intelligence data depends on provider coverage and may not reflect real-time threats. AI output is assistive and must be validated by a human analyst. A high risk score is not definitive proof of malicious intent.",
    provider: "Rule-Based Forensic Reasoning Engine",
  };
}

function buildExecutiveSummary(
  risk: RiskAssessment,
  authentication: AuthResult,
  findings: string[],
): string {
  const levelText = risk.level === "CRITICAL" ? "critical risk" :
    risk.level === "HIGH" ? "high risk" :
    risk.level === "MEDIUM" ? "moderate risk" : "low risk";

  const authSummary = [];
  if (authentication.spf !== "PASS" && authentication.spf !== "NONE") authSummary.push(`SPF ${authentication.spf}`);
  if (authentication.dkim !== "PASS" && authentication.dkim !== "NONE") authSummary.push(`DKIM ${authentication.dkim}`);
  if (authentication.dmarc !== "PASS" && authentication.dmarc !== "NONE") authSummary.push(`DMARC ${authentication.dmarc}`);

  const authText = authSummary.length > 0
    ? ` Authentication failures were detected (${authSummary.join(", ")}).`
    : "";

  const topFindings = findings.slice(0, 3).join(" ");

  return `This email has been assessed as ${levelText} with a threat score of ${risk.score}/100.${authText} ${topFindings} The analysis combines email authentication results, header forensic examination, indicator extraction, threat intelligence enrichment, and geolocation data to produce this assessment.`;
}

function interpretAttackTechnique(ctx: AIContext): string {
  const { anomalies, threatResults, indicators, authentication } = ctx;
  const techniques: string[] = [];

  if (anomalies.some((a) => a.type === "reply_to_mismatch" || a.type === "return_path_mismatch")) {
    techniques.push("Sender spoofing with reply-to redirection");
  }
  if (anomalies.some((a) => a.type === "display_name_spoofing")) {
    techniques.push("Brand impersonation via display name manipulation");
  }
  if (indicators.urls.some((u) => u.isPunycode)) {
    techniques.push("IDN homograph attack using punycode domains");
  }
  if (threatResults.some((t) => t.type === "url" && t.reputation === "malicious")) {
    techniques.push("Credential harvesting via malicious URLs");
  }
  if (indicators.attachments.some((a) => a.isDangerous)) {
    techniques.push("Malware delivery via malicious attachments");
  }
  if (authentication.spf === "FAIL" && authentication.dkim === "FAIL") {
    techniques.push("Email forgery with failed authentication (spoofed sending infrastructure)");
  }

  if (techniques.length === 0) {
    return "No specific attack technique was identified. The email may be legitimate or use techniques not covered by the current detection rules.";
  }

  return `Likely attack technique(s): ${techniques.join("; ")}. These techniques are commonly associated with phishing and social engineering campaigns.`;
}
