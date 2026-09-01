// Risk Engine — transparent scoring system with deduplication
import type { RiskAssessment, RiskFactor, HeaderAnomaly, AuthResult, Indicators, ThreatIntelResult, EmailMetadata, AttachmentInfo } from "./types";

export function calculateRisk(
  metadata: EmailMetadata,
  authentication: AuthResult,
  anomalies: HeaderAnomaly[],
  indicators: Indicators,
  threatResults: ThreatIntelResult[],
  attachments: AttachmentInfo[],
): RiskAssessment {
  const factors: RiskFactor[] = [];
  const seenCategories = new Set<string>();

  // Authentication failures
  if (authentication.spf === "FAIL" || authentication.spf === "SOFTFAIL") {
    const points = authentication.spf === "FAIL" ? 15 : 8;
    factors.push({
      name: "SPF Authentication Failure",
      points,
      evidence: `SPF result: ${authentication.spf}${authentication.spfDomain ? ` (domain: ${authentication.spfDomain})` : ""}`,
      category: "auth_spf",
      severity: points >= 15 ? "high" : "medium",
    });
  }

  if (authentication.dkim === "FAIL") {
    factors.push({
      name: "DKIM Authentication Failure",
      points: 15,
      evidence: `DKIM result: ${authentication.dkim}${authentication.dkimDomain ? ` (domain: ${authentication.dkimDomain})` : ""}`,
      category: "auth_dkim",
      severity: "high",
    });
  }

  if (authentication.dmarc === "FAIL" || authentication.dmarc === "NONE") {
    const points = authentication.dmarc === "FAIL" ? 10 : 5;
    factors.push({
      name: authentication.dmarc === "FAIL" ? "DMARC Authentication Failure" : "DMARC Policy Not Configured",
      points,
      evidence: `DMARC result: ${authentication.dmarc}${authentication.dmarcPolicy ? ` (policy: ${authentication.dmarcPolicy})` : ""}`,
      category: "auth_dmarc",
      severity: points >= 10 ? "medium" : "low",
    });
  }

  // Header anomalies
  for (const anomaly of anomalies) {
    const categoryKey = `anomaly_${anomaly.type}`;
    if (seenCategories.has(categoryKey)) continue;
    seenCategories.add(categoryKey);

    const pointsBySeverity = { info: 0, low: 5, medium: 12, high: 20 };
    const points = pointsBySeverity[anomaly.severity];
    if (points > 0) {
      factors.push({
        name: anomaly.description,
        points,
        evidence: anomaly.evidence,
        category: categoryKey,
        severity: anomaly.severity,
      });
    }
  }

  // Threat intelligence results for IPs
  const ipThreats = threatResults.filter((t) => t.type === "ip" && t.reputation !== "clean" && t.reputation !== "unknown");
  const maliciousIPs = ipThreats.filter((t) => t.reputation === "malicious");
  const suspiciousIPs = ipThreats.filter((t) => t.reputation === "suspicious");

  if (maliciousIPs.length > 0) {
    factors.push({
      name: "Malicious IP Address Detected",
      points: 25,
      evidence: `Known malicious IPs: ${maliciousIPs.map((t) => t.indicator).join(", ")}`,
      category: "malicious_ip",
      severity: "high",
    });
  } else if (suspiciousIPs.length > 0 && !seenCategories.has("suspicious_ip")) {
    seenCategories.add("suspicious_ip");
    factors.push({
      name: "Suspicious IP Address Detected",
      points: 15,
      evidence: `Suspicious IPs: ${suspiciousIPs.map((t) => t.indicator).join(", ")}`,
      category: "suspicious_ip",
      severity: "medium",
    });
  }

  // Threat intel for domains
  const domainThreats = threatResults.filter((t) => t.type === "domain" && t.reputation !== "clean" && t.reputation !== "unknown");
  const maliciousDomains = domainThreats.filter((t) => t.reputation === "malicious");
  if (maliciousDomains.length > 0) {
    factors.push({
      name: "Malicious Domain Detected",
      points: 20,
      evidence: `Malicious domains: ${maliciousDomains.map((t) => t.indicator).join(", ")}`,
      category: "malicious_domain",
      severity: "high",
    });
  }

  // Threat intel for URLs
  const urlThreats = threatResults.filter((t) => t.type === "url" && t.reputation !== "clean" && t.reputation !== "unknown");
  const maliciousURLs = urlThreats.filter((t) => t.reputation === "malicious");
  if (maliciousURLs.length > 0) {
    factors.push({
      name: "Malicious URL Detected",
      points: 30,
      evidence: `Malicious URLs: ${maliciousURLs.map((t) => t.indicator.slice(0, 80)).join(", ")}`,
      category: "malicious_url",
      severity: "high",
    });
  }

  // Threat intel for hashes
  const hashThreats = threatResults.filter((t) => t.type === "hash" && t.reputation === "malicious");
  if (hashThreats.length > 0) {
    factors.push({
      name: "Known Malicious File Hash",
      points: 40,
      evidence: `Malicious file hashes detected: ${hashThreats.length} attachment(s) flagged`,
      category: "malicious_hash",
      severity: "high",
    });
  }

  // Dangerous attachments
  const dangerousAttachments = attachments.filter((a) => a.isDangerous);
  if (dangerousAttachments.length > 0) {
    factors.push({
      name: "Dangerous Attachment Type",
      points: 20,
      evidence: `Potentially dangerous attachments: ${dangerousAttachments.map((a) => a.filename).join(", ")}`,
      category: "dangerous_attachment",
      severity: "high",
    });
  }

  // Punycode domain detection
  const punycodeDomains = indicators.urls.filter((u) => u.isPunycode);
  if (punycodeDomains.length > 0) {
    factors.push({
      name: "Punycode/IDN Domain Detected",
      points: 15,
      evidence: `Punycode domains (potential homograph attack): ${punycodeDomains.map((u) => u.domain).join(", ")}`,
      category: "punycode_domain",
      severity: "medium",
    });
  }

  // Suspicious language in subject
  const suspiciousSubjectKeywords = ["urgent", "verify", "account suspended", "password expired", "click here", "confirm your", "update your", "wire transfer", "invoice overdue"];
  const subjectLower = metadata.subject.toLowerCase();
  const matchedKeywords = suspiciousSubjectKeywords.filter((kw) => subjectLower.includes(kw));
  if (matchedKeywords.length > 0) {
    factors.push({
      name: "Suspicious Subject Line Language",
      points: Math.min(10 + matchedKeywords.length * 3, 20),
      evidence: `Subject contains urgency/social engineering indicators: "${matchedKeywords.join('", "')}"`,
      category: "suspicious_language",
      severity: "medium",
    });
  }

  // Calculate total score (cap at 100)
  const totalScore = Math.min(factors.reduce((sum, f) => sum + f.points, 0), 100);

  // Determine threat level
  let level: RiskAssessment["level"];
  if (totalScore <= 24) level = "LOW";
  else if (totalScore <= 49) level = "MEDIUM";
  else if (totalScore <= 74) level = "HIGH";
  else level = "CRITICAL";

  // Confidence based on number of factors and data availability
  const dataPoints = factors.length + (authentication.spf !== "NONE" ? 1 : 0) + (authentication.dkim !== "NONE" ? 1 : 0);
  const confidence = Math.min(0.5 + dataPoints * 0.05, 0.95);

  return {
    score: totalScore,
    level,
    confidence,
    factors: factors.sort((a, b) => b.points - a.points),
  };
}
