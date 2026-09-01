// Header Forensics — parse Received headers, detect anomalies, build mail hop timeline
import type { ReceivedHop, HeaderAnomaly, EmailMetadata } from "./types";
import { extractAllIPs, classifyIP } from "./ipUtils";

function extractIPFromText(text: string): string | null {
  const ips = extractAllIPs(text);
  // Prefer public IPs
  const publicIp = ips.find((ip) => classifyIP(ip) === "public");
  if (publicIp) return publicIp;
  return ips[0] || null;
}

function parseTimestamp(raw: string): { timestamp: string; timezone: string } {
  // Typical format: ; Tue, 01 Sep 2026 10:30:00 +0530
  const match = raw.match(/;\s*(.+)/);
  const dateStr = match ? match[1].trim() : raw.trim();
  const tzMatch = dateStr.match(/([+-]\d{4}|[A-Z]{3,4})/);
  return {
    timestamp: dateStr.split(/\s+/).slice(0, 6).join(" "),
    timezone: tzMatch ? tzMatch[1] : "",
  };
}

export function parseReceivedHeaders(rawHeaders: Record<string, string>): ReceivedHop[] {
  const receivedRaw = rawHeaders["received"] || "";
  if (!receivedRaw) return [];

  // Multiple received headers are joined by \n
  const receivedList = receivedRaw.split("\n").filter(Boolean);
  const hops: ReceivedHop[] = [];

  receivedList.forEach((raw, idx) => {
    const fromMatch = raw.match(/from\s+([^\s]+(?:\s+\([^)]+\))?)/i);
    const byMatch = raw.match(/by\s+([^\s;]+(?:\s+\([^)]+\))?)/i);
    const withMatch = raw.match(/with\s+([^\s;]+)/i);
    const idMatch = raw.match(/id\s+([^\s;]+)/i);
    const forMatch = raw.match(/for\s+<([^>]+)>/i);

    const fromText = fromMatch ? fromMatch[1].trim() : "";
    const byText = byMatch ? byMatch[1].trim() : "";

    // Extract hostname from "from" field
    let sourceHostname = fromText.replace(/\s*\([^)]*\)/g, "").trim();
    // Try to get hostname from parenthetical
    const parenMatch = fromText.match(/\(([^)]+)\)/);
    if (parenMatch) {
      const parenContent = parenMatch[1];
      const hostInParen = parenContent.match(/([\w.-]+)/);
      if (hostInParen && !sourceHostname) sourceHostname = hostInParen[1];
    }

    const sourceIp = extractIPFromText(raw) || "";
    const { timestamp, timezone } = parseTimestamp(raw);
    const protocol = withMatch ? withMatch[1].trim() : "";

    hops.push({
      raw: raw.trim(),
      from: fromText,
      by: byText,
      with: protocol,
      id: idMatch ? idMatch[1].trim() : "",
      forAddr: forMatch ? forMatch[1].trim() : "",
      timestamp,
      timezone,
      sourceIp,
      sourceHostname,
      protocol,
      index: idx,
    });
  });

  // Hops are in reverse chronological order (most recent first) in email headers
  // We keep them as-is but note the ordering
  return hops;
}

export function detectHeaderAnomalies(
  metadata: EmailMetadata,
  hops: ReceivedHop[]
): HeaderAnomaly[] {
  const anomalies: HeaderAnomaly[] = [];

  // 1. Reply-To mismatch
  if (metadata.replyTo && metadata.fromAddress) {
    const fromDomain = metadata.fromAddress.split("@")[1]?.toLowerCase();
    const replyDomain = metadata.replyTo.split("@")[1]?.toLowerCase().replace(/[<>]/g, "");
    if (replyDomain && fromDomain && replyDomain !== fromDomain) {
      anomalies.push({
        type: "reply_to_mismatch",
        description: "Reply-To address domain differs from From address domain",
        severity: "medium",
        evidence: `From: ${metadata.fromAddress} (domain: ${fromDomain}) | Reply-To: ${metadata.replyTo} (domain: ${replyDomain})`,
        category: "sender_spoofing",
      });
    }
  }

  // 2. Return-Path mismatch
  if (metadata.returnPath && metadata.fromAddress) {
    const returnPathAddr = metadata.returnPath.replace(/[<>]/g, "").trim();
    const returnDomain = returnPathAddr.split("@")[1]?.toLowerCase();
    const fromDomain = metadata.fromAddress.split("@")[1]?.toLowerCase();
    if (returnDomain && fromDomain && returnDomain !== fromDomain) {
      anomalies.push({
        type: "return_path_mismatch",
        description: "Return-Path domain differs from From domain",
        severity: "medium",
        evidence: `From: ${metadata.fromAddress} (domain: ${fromDomain}) | Return-Path: ${returnPathAddr} (domain: ${returnDomain})`,
        category: "sender_spoofing",
      });
    }
  }

  // 3. Display name spoofing
  if (metadata.fromName && metadata.fromAddress) {
    const fromDomain = metadata.fromAddress.split("@")[1]?.toLowerCase() || "";
    const nameLower = metadata.fromName.toLowerCase();
    // Check if display name contains a different domain or common brand names
    const commonBrands = ["paypal", "google", "microsoft", "apple", "amazon", "bank", "secure", "account", "support"];
    const nameHasBrand = commonBrands.some((b) => nameLower.includes(b));
    const isFreeEmail = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"].includes(fromDomain);
    if (nameHasBrand && isFreeEmail) {
      anomalies.push({
        type: "display_name_spoofing",
        description: "Display name impersonates a known brand while using a free email provider",
        severity: "high",
        evidence: `Display name: "${metadata.fromName}" uses free email address: ${metadata.fromAddress}`,
        category: "sender_spoofing",
      });
    }
  }

  // 4. Suspicious relay chain — check for private IP in middle hops
  hops.forEach((hop) => {
    if (hop.sourceIp) {
      const cls = classifyIP(hop.sourceIp);
      if (cls === "private" && hop.index > 0) {
        anomalies.push({
          type: "private_ip_in_chain",
          description: `Private IP address ${hop.sourceIp} found in Received header hop ${hop.index + 1}`,
          severity: "low",
          evidence: `Hop ${hop.index + 1}: ${hop.raw.slice(0, 100)}`,
          category: "relay_chain",
        });
      }
    }
  });

  // 5. Inconsistent timestamps — check if timestamps are out of order
  const timestamps = hops
    .filter((h) => h.timestamp)
    .map((h) => ({ idx: h.index, date: new Date(h.timestamp) }))
    .filter((t) => !isNaN(t.date.getTime()));

  for (let i = 1; i < timestamps.length; i++) {
    // Headers are most-recent-first, so earlier headers (higher index) should have earlier times
    if (timestamps[i].date > timestamps[i - 1].date) {
      anomalies.push({
        type: "timestamp_inconsistency",
        description: "Mail hop timestamps are not in expected chronological order",
        severity: "medium",
        evidence: `Hop ${timestamps[i].idx + 1} timestamp is later than hop ${timestamps[i - 1].idx + 1}`,
        category: "relay_chain",
      });
      break;
    }
  }

  // 6. Missing or empty Message-ID
  if (!metadata.messageId) {
    anomalies.push({
      type: "missing_message_id",
      description: "Message-ID header is missing",
      severity: "low",
      evidence: "No Message-ID header found in the email",
      category: "header_structure",
    });
  }

  // 7. Excessive received hops (>5 is unusual for legitimate email)
  if (hops.length > 6) {
    anomalies.push({
      type: "excessive_hops",
      description: `Email passed through ${hops.length} mail servers, which is unusually high`,
      severity: "low",
      evidence: `${hops.length} Received headers found`,
      category: "relay_chain",
    });
  }

  // 8. X-Mailer / User-Agent anomaly — known suspicious mailers
  const suspiciousMailers = ["phpmailer", "mailgun", "sendgrid", "bombphp", "spam"];
  const mailerLower = metadata.userAgent.toLowerCase();
  if (suspiciousMailers.some((m) => mailerLower.includes(m))) {
    anomalies.push({
      type: "suspicious_mailer",
      description: `Email was sent using a commonly abused mail client: ${metadata.userAgent}`,
      severity: "low",
      evidence: `User-Agent/X-Mailer: ${metadata.userAgent}`,
      category: "header_structure",
    });
  }

  return anomalies;
}
