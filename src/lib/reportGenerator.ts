// Report Generator — generates downloadable HTML and JSON reports
import type { AnalysisResult } from "./types";

export function generateJSONReport(result: AnalysisResult): string {
  return JSON.stringify(result, null, 2);
}

export function generateHTMLReport(result: AnalysisResult): string {
  const riskColor = {
    LOW: "#22c55e",
    MEDIUM: "#eab308",
    HIGH: "#f97316",
    CRITICAL: "#ef4444",
  }[result.risk.level];

  const authBadge = (val: string) => {
    const color = val === "PASS" ? "#22c55e" : val === "FAIL" ? "#ef4444" : val === "NONE" || val === "UNKNOWN" ? "#6b7280" : "#eab308";
    return `<span style="display:inline-block;padding:2px 12px;border-radius:4px;background:${color};color:#fff;font-weight:600;font-size:12px;">${val}</span>`;
  };

  const formatValue = (v: unknown): string => {
    if (v === null || v === undefined || v === "") return "<em style='color:#888'>N/A</em>";
    return String(v);
  };

  const iocTable = result.threatIntelligence.map((t) => `
    <tr>
      <td style="padding:6px;border:1px solid #333;font-family:monospace;">${t.indicator.slice(0, 60)}</td>
      <td style="padding:6px;border:1px solid #333;text-transform:uppercase;">${t.type}</td>
      <td style="padding:6px;border:1px solid #333;color:${t.reputation === "malicious" ? "#ef4444" : t.reputation === "suspicious" ? "#eab308" : "#22c55e"};font-weight:600;text-transform:uppercase;">${t.reputation}</td>
      <td style="padding:6px;border:1px solid #333;">${t.score}</td>
      <td style="padding:6px;border:1px solid #333;">${t.detections}</td>
      <td style="padding:6px;border:1px solid #333;font-size:12px;">${t.details.slice(0, 80)}</td>
    </tr>`).join("");

  const geoRows = result.geolocation.map((g) => `
    <tr>
      <td style="padding:6px;border:1px solid #333;font-family:monospace;">${g.ip}</td>
      <td style="padding:6px;border:1px solid #333;">${g.success ? `${g.city}, ${g.region}, ${g.country}` : "Geolocation unavailable"}</td>
      <td style="padding:6px;border:1px solid #333;">${g.isp || "N/A"}</td>
      <td style="padding:6px;border:1px solid #333;">${g.asn || "N/A"}</td>
      <td style="padding:6px;border:1px solid #333;">${g.success ? `${g.latitude.toFixed(4)}, ${g.longitude.toFixed(4)}` : "N/A"}</td>
    </tr>`).join("");

  const riskFactorsHtml = result.risk.factors.map((f) => `
    <tr>
      <td style="padding:6px;border:1px solid #333;">${f.name}</td>
      <td style="padding:6px;border:1px solid #333;color:${f.points >= 20 ? "#ef4444" : f.points >= 10 ? "#eab308" : "#888"};font-weight:600;">+${f.points}</td>
      <td style="padding:6px;border:1px solid #333;font-size:12px;">${f.evidence.slice(0, 100)}</td>
    </tr>`).join("");

  const hopRows = result.headers.map((h, i) => `
    <tr>
      <td style="padding:6px;border:1px solid #333;">Hop ${i + 1}</td>
      <td style="padding:6px;border:1px solid #333;font-family:monospace;">${h.sourceIp || "N/A"}</td>
      <td style="padding:6px;border:1px solid #333;">${h.sourceHostname || "N/A"}</td>
      <td style="padding:6px;border:1px solid #333;font-size:12px;">${h.timestamp || "N/A"}</td>
      <td style="padding:6px;border:1px solid #333;font-size:12px;">${h.by || "N/A"}</td>
    </tr>`).join("");

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>CybroatriX Forensic Report — ${result.investigationId}</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: 'Segoe UI', Arial, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 20px; line-height: 1.6; }
  .container { max-width: 900px; margin: 0 auto; background: #1e293b; border-radius: 12px; padding: 40px; border: 1px solid #334155; }
  h1 { color: #38bdf8; border-bottom: 2px solid #334155; padding-bottom: 10px; }
  h2 { color: #38bdf8; margin-top: 30px; border-bottom: 1px solid #334155; padding-bottom: 8px; }
  h3 { color: #7dd3fc; margin-top: 20px; }
  table { width: 100%; border-collapse: collapse; margin: 10px 0; font-size: 14px; }
  th { background: #334155; padding: 8px; border: 1px solid #475569; text-align: left; color: #cbd5e1; }
  .risk-badge { display: inline-block; padding: 6px 20px; border-radius: 8px; background: ${riskColor}; color: #fff; font-weight: 700; font-size: 18px; }
  .meta-grid { display: grid; grid-template-columns: 150px 1fr; gap: 4px 12px; margin: 10px 0; }
  .meta-grid dt { color: #94a3b8; font-weight: 600; }
  .meta-grid dd { margin: 0; font-family: monospace; word-break: break-all; }
  .section { margin: 25px 0; }
  .limitations { background: #1e293b; border-left: 4px solid #f97316; padding: 15px; margin: 15px 0; }
  .ai-box { background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 20px; margin: 15px 0; }
  .footer { margin-top: 40px; padding-top: 15px; border-top: 1px solid #334155; color: #64748b; font-size: 12px; }
  ul { padding-left: 20px; } li { margin: 4px 0; }
</style>
</head>
<body>
<div class="container">
  <h1>CybroatriX Email Forensics AI</h1>
  <p style="color:#94a3b8;">Connect &bull; Innovate &bull; Empower</p>
  <div style="margin:20px 0;">
    <strong>Investigation ID:</strong> ${result.investigationId}<br>
    <strong>Analyzed:</strong> ${new Date(result.analyzedAt).toLocaleString()}<br>
    <strong>File:</strong> ${result.filename}
  </div>

  <div class="section">
    <h2>1. Executive Summary</h2>
    <div class="risk-badge">${result.risk.level} — Score: ${result.risk.score}/100</div>
    <p style="margin-top:15px;">${result.aiAssessment.executiveSummary}</p>
    <p><strong>Confidence:</strong> ${result.aiAssessment.confidence}</p>
  </div>

  <div class="section">
    <h2>2. Email Metadata</h2>
    <dl class="meta-grid">
      <dt>From</dt><dd>${formatValue(result.email.from)}</dd>
      <dt>To</dt><dd>${formatValue(result.email.to.join(", "))}</dd>
      <dt>Subject</dt><dd>${formatValue(result.email.subject)}</dd>
      <dt>Date</dt><dd>${formatValue(result.email.date)}</dd>
      <dt>Reply-To</dt><dd>${formatValue(result.email.replyTo)}</dd>
      <dt>Return-Path</dt><dd>${formatValue(result.email.returnPath)}</dd>
      <dt>Message-ID</dt><dd>${formatValue(result.email.messageId)}</dd>
    </dl>
  </div>

  <div class="section">
    <h2>3. Authentication Analysis</h2>
    <table>
      <tr><th>SPF</th><th>DKIM</th><th>DMARC</th><th>ARC</th></tr>
      <tr>
        <td style="text-align:center;padding:10px;border:1px solid #333;">${authBadge(result.authentication.spf)}</td>
        <td style="text-align:center;padding:10px;border:1px solid #333;">${authBadge(result.authentication.dkim)}</td>
        <td style="text-align:center;padding:10px;border:1px solid #333;">${authBadge(result.authentication.dmarc)}</td>
        <td style="text-align:center;padding:10px;border:1px solid #333;">${authBadge(result.authentication.arc)}</td>
      </tr>
    </table>
    <p style="font-size:12px;color:#94a3b8;">${result.authentication.authDetails || "No authentication details available"}</p>
  </div>

  <div class="section">
    <h2>4. Header Forensics — Mail Hop Timeline</h2>
    ${result.headers.length > 0 ? `<table><tr><th>Hop</th><th>Source IP</th><th>Hostname</th><th>Timestamp</th><th>Received By</th></tr>${hopRows}</table>` : "<p>No Received headers found.</p>"}
    ${result.anomalies.length > 0 ? `<h3>Header Anomalies (${result.anomalies.length})</h3><ul>${result.anomalies.map((a) => `<li><strong>${a.description}</strong> <span style="color:${a.severity === "high" ? "#ef4444" : a.severity === "medium" ? "#eab308" : "#94a3b8"}">[${a.severity.toUpperCase()}]</span><br><span style="font-size:12px;color:#94a3b8;">${a.evidence}</span></li>`).join("")}</ul>` : "<p>No header anomalies detected.</p>"}
  </div>

  <div class="section">
    <h2>5. Threat Intelligence Findings</h2>
    ${result.threatIntelligence.length > 0 ? `<table><tr><th>Indicator</th><th>Type</th><th>Reputation</th><th>Score</th><th>Detections</th><th>Details</th></tr>${iocTable}</table>` : "<p>No threat intelligence data available.</p>"}
  </div>

  <div class="section">
    <h2>6. IP Geolocation</h2>
    ${result.geolocation.length > 0 ? `<table><tr><th>IP</th><th>Location</th><th>ISP</th><th>ASN</th><th>Coordinates</th></tr>${geoRows}</table>` : "<p>No publicly routable IP addresses were available for geographic mapping.</p>"}
  </div>

  <div class="section">
    <h2>7. Threat Score Breakdown</h2>
    <table><tr><th>Risk Factor</th><th>Points</th><th>Evidence</th></tr>${riskFactorsHtml}</table>
    <p style="margin-top:10px;"><strong>Total Score: ${result.risk.score}/100 — Level: ${result.risk.level}</strong></p>
  </div>

  <div class="section">
    <h2>8. AI Investigation Assessment</h2>
    <div class="ai-box">
      <h3>Executive Summary</h3>
      <p>${result.aiAssessment.executiveSummary}</p>
      <h3>Why This Email Is Suspicious</h3>
      <p>${result.aiAssessment.whySuspicious}</p>
      <h3>Key Evidence</h3>
      <ul>${result.aiAssessment.keyEvidence.map((e) => `<li>${e}</li>`).join("")}</ul>
      <h3>Attack Technique Interpretation</h3>
      <p>${result.aiAssessment.attackTechnique}</p>
      <h3>Recommended Actions</h3>
      <ul>${result.aiAssessment.recommendedActions.map((r) => `<li>${r}</li>`).join("")}</ul>
    </div>
  </div>

  <div class="section limitations">
    <h2>9. Limitations &amp; Disclaimers</h2>
    <p>${result.aiAssessment.limitations}</p>
    <ul>
      <li>IP geolocation is approximate and does not identify a person or exact physical location.</li>
      <li>The most recent public mail server is not automatically the original attacker IP.</li>
      <li>Email headers can be spoofed or manipulated.</li>
      <li>Missing SPF/DKIM/DMARC data is not automatically proof of maliciousness.</li>
      <li>AI output is assistive and must be validated by an analyst.</li>
    </ul>
  </div>

  <div class="footer">
    <p>Generated by CybroatriX Email Forensics AI — ${new Date().toISOString()}</p>
    <p>Investigation ID: ${result.investigationId}</p>
  </div>
</div>
</body>
</html>`;
}

export function downloadFile(content: string, filename: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
