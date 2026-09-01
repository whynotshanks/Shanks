// Email Authentication Analyzer — SPF, DKIM, DMARC, ARC
import type { AuthResult } from "./types";

export function analyzeEmailAuth(rawHeaders: Record<string, string>): AuthResult {
  // Look for Authentication-Results header (most reliable source in parsed email)
  const authResultsHeader = rawHeaders["authentication-results"] || "";
  const receivedSPF = rawHeaders["received-spf"] || "";
  const dkimSignature = rawHeaders["dkim-signature"] || "";
  const arcHeader = rawHeaders["arc-authentication-results"] || rawHeaders["arc-message-signature"] || "";

  let spf = "NONE";
  let dkim = "NONE";
  let dmarc = "NONE";
  let arc = "NONE";

  let spfDomain = "";
  let spfRecord = "";
  let dkimDomain = "";
  let dkimSelector = "";
  let dmarcPolicy = "";

  const authDetails: string[] = [];

  // Parse Authentication-Results header
  if (authResultsHeader) {
    const lines = authResultsHeader.split("\n");
    for (const line of lines) {
      const lower = line.toLowerCase();

      // SPF
      const spfMatch = line.match(/spf\s*=\s*(\w+)/i);
      if (spfMatch) {
        spf = spfMatch[1].toUpperCase();
        const domainMatch = line.match(/spf\s*=\s*\w+\s+\(([^)]+)\)/i);
        if (domainMatch) spfDomain = domainMatch[1];
      }

      // DKIM
      const dkimMatch = line.match(/dkim\s*=\s*(\w+)/i);
      if (dkimMatch) {
        dkim = dkimMatch[1].toUpperCase();
        const headerDMatch = line.match(/header\.d\s*=\s*([^;\s]+)/i);
        if (headerDMatch) dkimDomain = headerDMatch[1];
      }

      // DMARC
      const dmarcMatch = line.match(/dmarc\s*=\s*(\w+)/i);
      if (dmarcMatch) {
        dmarc = dmarcMatch[1].toUpperCase();
        const policyMatch = line.match(/policy\.?\s*=?\s*(\w+)/i);
        if (policyMatch) dmarcPolicy = policyMatch[1];
      }

      // ARC
      const arcMatch = line.match(/arc\s*=\s*(\w+)/i);
      if (arcMatch) arc = arcMatch[1].toUpperCase();
    }
    authDetails.push(authResultsHeader);
  }

  // Fallback: parse Received-SPF header
  if (spf === "NONE" && receivedSPF) {
    const spfResultMatch = receivedSPF.match(/^(\w+)\s/i) || receivedSPF.match(/result\s*=\s*(\w+)/i);
    if (spfResultMatch) spf = spfResultMatch[1].toUpperCase();
    const domainMatch = receivedSPF.match(/domain\s*=\s*([^\s;]+)/i);
    if (domainMatch) spfDomain = domainMatch[1];
    spfRecord = receivedSPF;
    authDetails.push(`Received-SPF: ${receivedSPF}`);
  }

  // Fallback: parse DKIM-Signature header for domain/selector
  if (dkimSignature) {
    const dMatch = dkimSignature.match(/d\s*=\s*([^;]+)/i);
    if (dMatch && !dkimDomain) dkimDomain = dMatch[1].trim();
    const sMatch = dkimSignature.match(/s\s*=\s*([^;]+)/i);
    if (sMatch) dkimSelector = sMatch[1].trim();
    if (dkim === "NONE") {
      // Presence of DKIM-Signature without Authentication-Results means we can't verify
      dkim = "UNKNOWN";
    }
    authDetails.push(`DKIM-Signature present (d=${dkimDomain}, s=${dkimSelector})`);
  }

  if (arcHeader) {
    arc = "PRESENT";
    authDetails.push(`ARC: ${arcHeader.slice(0, 100)}`);
  }

  return {
    spf,
    dkim,
    dmarc,
    arc,
    spfDomain,
    spfRecord,
    dkimDomain,
    dkimSelector,
    dmarcPolicy,
    authDetails: authDetails.join("\n"),
  };
}
