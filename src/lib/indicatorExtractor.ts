// Indicator (IOC) Extractor — extracts IPs, domains, URLs, email addresses, hashes
import type { EmailMetadata, Indicators, AttachmentInfo, IPIndicator, DomainIndicator, URLIndicator, HashIndicator, EmailAddrIndicator } from "./types";
import { extractAllIPs, classifyIP } from "./ipUtils";

const URL_REGEX = /https?:\/\/[^\s<>"'\\]+/gi;
const DOMAIN_REGEX = /\b(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b)/gi;
const EMAIL_REGEX = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;

// Punycode detection (xn-- prefix)
function isPunycodeDomain(domain: string): boolean {
  return domain.toLowerCase().includes("xn--");
}

function extractDomainsFromUrl(url: string): string {
  try {
    const u = new URL(url);
    return u.hostname.toLowerCase();
  } catch {
    const match = url.match(/^https?:\/\/([^/]+)/i);
    return match ? match[1].toLowerCase() : "";
  }
}

export function extractIndicators(
  metadata: EmailMetadata,
  attachments: AttachmentInfo[],
  receivedHops: { sourceIp: string }[],
): Indicators {
  const fullText = [
    metadata.subject,
    metadata.textBody,
    metadata.htmlBody,
    metadata.from,
    metadata.replyTo,
    metadata.returnPath,
    metadata.to.join(" "),
    metadata.cc.join(" "),
    metadata.bcc.join(" "),
  ].join("\n");

  // Extract IPs from body + headers (Received headers are handled separately)
  const rawHeaderText = JSON.stringify(metadata.rawHeaders);
  const allIPText = fullText + "\n" + rawHeaderText;
  const ipStrings = extractAllIPs(allIPText);

  // Also add IPs from received hops
  for (const hop of receivedHops) {
    if (hop.sourceIp && !ipStrings.includes(hop.sourceIp)) {
      ipStrings.push(hop.sourceIp);
    }
  }

  const ips: IPIndicator[] = ipStrings
    .filter((ip) => classifyIP(ip) !== "invalid")
    .map((ip) => ({
      address: ip,
      type: ip.includes(":") ? "ipv6" : ("ipv4" as "ipv4" | "ipv6"),
      classification: classifyIP(ip),
      source: "email_headers_body",
      threat: null,
      geo: null,
    }));

  // Extract URLs
  const urlMatches = fullText.match(URL_REGEX) || [];
  const uniqueUrls = [...new Set(urlMatches.map((u) => u.replace(/[.,;:]+$/, "")))];
  const urls: URLIndicator[] = uniqueUrls.map((url) => {
    const domain = extractDomainsFromUrl(url);
    return {
      url,
      domain,
      source: "email_body",
      threat: null,
      isPunycode: isPunycodeDomain(domain),
    };
  });

  // Extract domains (from URLs and email addresses, not random text matches to reduce noise)
  const domainsFromUrls = urls.map((u) => u.domain).filter(Boolean);
  const domainsFromEmails: string[] = [];
  const allEmails = [
    metadata.fromAddress,
    ...metadata.to,
    metadata.replyTo,
    metadata.returnPath.replace(/[<>]/g, ""),
  ].filter(Boolean);
  for (const email of allEmails) {
    const domain = email.split("@")[1]?.toLowerCase().replace(/[<>]/g, "");
    if (domain) domainsFromEmails.push(domain);
  }

  const allDomains = [...new Set([...domainsFromUrls, ...domainsFromEmails])];
  const domains: DomainIndicator[] = allDomains
    .filter((d) => d && d.includes(".") && !d.match(/^\d+\.\d+\.\d+\.\d+$/))
    .map((domain) => ({
      domain,
      source: domainsFromUrls.includes(domain) ? "url" : "email_address",
      threat: null,
    }));

  // Extract email addresses
  const emailMatches = fullText.match(EMAIL_REGEX) || [];
  const allEmailAddresses = [...new Set([...emailMatches, ...allEmails.filter((e) => e.includes("@"))])];
  const emailAddresses: EmailAddrIndicator[] = allEmailAddresses.map((address) => ({
    address: address.replace(/[<>]/g, "").trim(),
    source: "email_content",
  }));

  // Hash indicators from attachments
  const hashes: HashIndicator[] = [];
  for (const att of attachments) {
    if (att.sha256) {
      hashes.push({ fileName: att.filename, hashType: "sha256", hash: att.sha256, threat: null });
    }
    if (att.sha1) {
      hashes.push({ fileName: att.filename, hashType: "sha1", hash: att.sha1, threat: null });
    }
    if (att.md5) {
      hashes.push({ fileName: att.filename, hashType: "md5", hash: att.md5, threat: null });
    }
  }

  return {
    ips,
    domains,
    urls,
    hashes,
    emailAddresses,
    attachments,
  };
}
