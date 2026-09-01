// IP address utilities — classification, extraction, validation

const IPV4_REGEX = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const IPV6_REGEX = /(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|::[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6})\b/g;

export function extractIPv4(text: string): string[] {
  const matches = text.match(IPV4_REGEX) || [];
  return [...new Set(matches)];
}

export function extractIPv6(text: string): string[] {
  const matches = text.match(IPV6_REGEX) || [];
  return [...new Set(matches.filter((ip) => ip.length > 3 && ip !== "::"))];
}

export type IPClassification = "public" | "private" | "loopback" | "link-local" | "invalid";

export function classifyIPv4(ip: string): IPClassification {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) return "invalid";

  const [a, b] = parts;

  if (a === 10) return "private";
  if (a === 172 && b >= 16 && b <= 31) return "private";
  if (a === 192 && b === 168) return "private";
  if (a === 127) return "loopback";
  if (a === 169 && b === 254) return "link-local";
  if (a === 0 || (a === 255 && b === 255 && parts[2] === 255 && parts[3] === 255)) return "invalid";

  return "public";
}

export function classifyIPv6(ip: string): IPClassification {
  const lower = ip.toLowerCase();
  if (lower === "::1") return "loopback";
  if (lower === "::") return "invalid";
  if (lower.startsWith("fe80")) return "link-local";
  if (lower.startsWith("fc") || lower.startsWith("fd")) return "private";
  if (lower.startsWith("::ffff:")) {
    const v4Part = lower.slice(7);
    if (/^\d+\.\d+\.\d+\.\d+$/.test(v4Part)) return classifyIPv4(v4Part);
  }
  return "public";
}

export function classifyIP(ip: string): IPClassification {
  if (ip.includes(":")) return classifyIPv6(ip);
  return classifyIPv4(ip);
}

export function isPrivateIP(ip: string): boolean {
  const c = classifyIP(ip);
  return c === "private" || c === "loopback" || c === "link-local";
}

export function isPublicIP(ip: string): boolean {
  return classifyIP(ip) === "public";
}

export function isValidIP(ip: string): boolean {
  return classifyIP(ip) !== "invalid";
}

export function extractAllIPs(text: string): string[] {
  return [...new Set([...extractIPv4(text), ...extractIPv6(text)])];
}
