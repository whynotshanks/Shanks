// EML Parser — parses raw EML content using browser APIs and manual parsing
import type { EmailMetadata, EmailAddress, AttachmentInfo } from "./types";

// Web Crypto API hashing
async function digest(data: ArrayBuffer, algorithm: "MD5" | "SHA-1" | "SHA-256"): Promise<string> {
  // MD5 not available in Web Crypto, so use a simple JS implementation
  if (algorithm === "MD5") {
    return md5(new Uint8Array(data));
  }
  const hashBuffer = await crypto.subtle.digest(algorithm, data);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Minimal MD5 implementation
function md5(data: Uint8Array): string {
  function toUtf8(str: string): Uint8Array {
    return new TextEncoder().encode(str);
  }
  const msg = data;
  // MD5 constants
  const s = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
  const K = new Uint32Array([
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
  ]);

  const n = msg.length;
  const bitLen = BigInt(n) * 8n;
  // Padding
  const padded: number[] = Array.from(msg);
  padded.push(0x80);
  while (padded.length % 64 !== 56) padded.push(0);
  for (let i = 0; i < 8; i++) padded.push(Number((bitLen >> BigInt(i * 8)) & 0xffn));

  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;

  for (let off = 0; off < padded.length; off += 64) {
    const M = new Uint32Array(16);
    for (let j = 0; j < 16; j++) {
      M[j] = (padded[off + j * 4]) | (padded[off + j * 4 + 1] << 8) |
        (padded[off + j * 4 + 2] << 16) | (padded[off + j * 4 + 3] << 24);
    }
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F: number; let g: number;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      F = (F + A + K[i] + M[g]) >>> 0;
      A = D; D = C; C = B;
      B = (B + ((F << s[i]) | (F >>> (32 - s[i])))) >>> 0;
    }
    a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0;
    c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
  }

  const toHex = (x: number) => {
    let h = "";
    for (let i = 0; i < 4; i++) h += ((x >>> (i * 8)) & 0xff).toString(16).padStart(2, "0");
    return h;
  };
  void toUtf8;
  return toHex(a0) + toHex(b0) + toHex(c0) + toHex(d0);
}

function parseEmailAddress(raw: string): { name: string; address: string } {
  const trimmed = raw.trim();
  const angleMatch = trimmed.match(/^"?([^"<]*?)"?\s*<([^>]+)>$/);
  if (angleMatch) {
    return { name: angleMatch[1].trim().replace(/^"|"$/g, ""), address: angleMatch[2].trim() };
  }
  const bareEmail = trimmed.match(/<?([^@\s<>]+@[^@\s<>]+)>?$/);
  if (bareEmail) return { name: "", address: bareEmail[1].trim() };
  return { name: trimmed, address: trimmed };
}

function splitAddresses(raw: string): string[] {
  if (!raw) return [];
  return raw.split(",").map((s) => s.trim()).filter(Boolean);
}

function decodeQuotedPrintable(text: string): string {
  // Soft line breaks
  text = text.replace(/=\r?\n/g, "");
  // QP decode
  text = text.replace(/=([0-9A-Fa-f]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
  return text;
}

function decodeBase64Utf8(text: string): string {
  try {
    const cleaned = text.replace(/[^A-Za-z0-9+/=]/g, "");
    const binary = atob(cleaned);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return new TextDecoder("utf-8").decode(bytes);
  } catch {
    return text;
  }
}

function decodeEncodedWords(text: string): string {
  if (!text) return text;
  return text.replace(/=\?([^?]+)\?([BbQq])\?([^?]+)\?=/g, (_, charset, encoding, content) => {
    try {
      if (encoding.toUpperCase() === "B") {
        return decodeBase64Utf8(content);
      } else {
        let decoded = content.replace(/_/g, " ");
        decoded = decoded.replace(/=([0-9A-Fa-f]{2})/g, (_match: string, hex: string) => String.fromCharCode(parseInt(hex, 16)));
        try { return new TextDecoder(charset.toLowerCase()).decode(new TextEncoder().encode(decoded)); }
        catch { return decoded; }
      }
    } catch { return content; }
  });
}

interface ParsedMimePart {
  headers: Record<string, string>;
  contentType: string;
  contentTransferEncoding: string;
  contentDisposition: string;
  filename: string | null;
  body: string;
  isAttachment: boolean;
  parts: ParsedMimePart[];
  rawContent: ArrayBuffer | null;
}

function parseHeaders(headerBlock: string): Record<string, string> {
  const headers: Record<string, string> = {};
  // Unfold continuation lines (leading whitespace)
  const unfolded = headerBlock.replace(/\r?\n[ \t]+/g, " ");
  const lines = unfolded.split(/\r?\n/);
  for (const line of lines) {
    const colonIdx = line.indexOf(":");
    if (colonIdx === -1) continue;
    const key = line.slice(0, colonIdx).trim().toLowerCase();
    const value = line.slice(colonIdx + 1).trim();
    if (key) {
      if (headers[key] !== undefined) {
        headers[key] += "\n" + value;
      } else {
        headers[key] = value;
      }
    }
  }
  return headers;
}

function getBoundary(contentType: string): string | null {
  const match = contentType.match(/boundary\s*=\s*"?([^";\s]+)"?/i);
  return match ? match[1] : null;
}

function getCharset(contentType: string): string {
  const match = contentType.match(/charset\s*=\s*"?([^";\s]+)"?/i);
  return match ? match[1].toLowerCase() : "utf-8";
}

function parseMimePart(raw: string, headers: Record<string, string>): ParsedMimePart {
  const contentType = headers["content-type"] || "text/plain";
  const cte = (headers["content-transfer-encoding"] || "7bit").toLowerCase();
  const disposition = headers["content-disposition"] || "";
  let filename: string | null = null;
  const fnameMatch = disposition.match(/filename\s*=\s*"?([^";]+)"?/i) ||
    contentType.match(/name\s*=\s*"?([^";]+)"?/i);
  if (fnameMatch) filename = decodeEncodedWords(fnameMatch[1].trim());

  const isAttachment = /attachment/i.test(disposition) || (filename !== null && !/^text\/(plain|html)/i.test(contentType));
  const boundary = getBoundary(contentType);

  let body = raw;
  let textBody = "";
  let rawContent: ArrayBuffer | null = null;
  const subParts: ParsedMimePart[] = [];

  if (boundary && raw.includes("--" + boundary)) {
    const partsRaw = raw.split(new RegExp("--" + escapeRegex(boundary) + "(?:--)?\\r?\\n?", "g"))
      .filter((p) => p.trim() && !p.startsWith("--"));
    for (const partRaw of partsRaw) {
      const sepIdx = partRaw.indexOf("\r\n\r\n") >= 0 ? partRaw.indexOf("\r\n\r\n") : partRaw.indexOf("\n\n");
      const partHeadersRaw = sepIdx >= 0 ? partRaw.slice(0, sepIdx) : "";
      const partBody = sepIdx >= 0 ? partRaw.slice(sepIdx + (partRaw[sepIdx] === "\r" ? 4 : 2)) : "";
      const partHeaders = parseHeaders(partHeadersRaw);
      subParts.push(parseMimePart(partBody, partHeaders));
    }
  } else {
    // Leaf part — decode content
    if (cte === "base64") {
      try {
        const cleaned = raw.replace(/[^A-Za-z0-9+/=]/g, "");
        const binary = atob(cleaned);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        rawContent = bytes.buffer;
        if (/^text\//i.test(contentType) || contentType === "") {
          textBody = new TextDecoder(getCharset(contentType)).decode(bytes);
        }
      } catch { textBody = raw; }
    } else if (cte === "quoted-printable") {
      textBody = decodeQuotedPrintable(raw);
    } else {
      textBody = raw;
    }
  }

  return {
    headers,
    contentType,
    contentTransferEncoding: cte,
    contentDisposition: disposition,
    filename,
    body: textBody,
    isAttachment,
    parts: subParts,
    rawContent,
  };
}

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function flattenParts(part: ParsedMimePart, acc: ParsedMimePart[]): void {
  if (part.parts.length > 0) {
    for (const sub of part.parts) flattenParts(sub, acc);
  } else {
    acc.push(part);
  }
}

function getDomainFromEmail(email: string): string {
  const match = email.match(/@([^>]+)/);
  return match ? match[1].toLowerCase().trim() : "";
}

const DANGEROUS_EXTENSIONS = [
  ".exe", ".bat", ".cmd", ".com", ".scr", ".vbs", ".js", ".jar",
  ".ps1", ".msi", ".dll", ".sh", ".zip", ".rar", ".7z", ".iso",
  ".hta", ".cpl", ".wsf", ".vbe", ".jse", ".xlsb", ".xlsm", ".docm",
];

export async function parseEML(rawText: string): Promise<{
  metadata: EmailMetadata;
  attachments: AttachmentInfo[];
}> {
  // Split headers and body
  const headerEndIdx = rawText.indexOf("\r\n\r\n") >= 0
    ? rawText.indexOf("\r\n\r\n")
    : rawText.indexOf("\n\n");
  const headerBlock = headerEndIdx >= 0 ? rawText.slice(0, headerEndIdx) : rawText;
  const bodyBlock = headerEndIdx >= 0
    ? rawText.slice(headerEndIdx + (rawText[headerEndIdx] === "\r" ? 4 : 2))
    : "";

  const headers = parseHeaders(headerBlock);
  const rootContentType = headers["content-type"] || "text/plain";
  const rootPart = parseMimePart(bodyBlock, { "content-type": rootContentType, "content-transfer-encoding": headers["content-transfer-encoding"] || "7bit" });

  // Collect all leaf parts
  const allParts: ParsedMimePart[] = [];
  flattenParts(rootPart, allParts);

  let textBody = "";
  let htmlBody = "";
  const attachmentParts: ParsedMimePart[] = [];

  for (const part of allParts) {
    if (part.isAttachment) {
      attachmentParts.push(part);
    } else if (/^text\/plain/i.test(part.contentType)) {
      textBody = part.body || textBody;
    } else if (/^text\/html/i.test(part.contentType)) {
      htmlBody = part.body || htmlBody;
    }
  }

  // If no text body but html exists, derive a rough text version
  if (!textBody && htmlBody) {
    textBody = htmlBody.replace(/<[^>]+>/g, " ").replace(/&nbsp;/g, " ").replace(/\s+/g, " ").trim();
  }

  // Parse attachments
  const attachments: AttachmentInfo[] = [];
  for (const att of attachmentParts) {
    const filename = att.filename || "unknown_attachment";
    const ext = filename.includes(".") ? "." + filename.split(".").pop()!.toLowerCase() : "";
    const isDangerous = DANGEROUS_EXTENSIONS.includes(ext);
    let sha256 = "", sha1 = "", md5hash = "";
    if (att.rawContent) {
      try {
        sha256 = await digest(att.rawContent, "SHA-256");
        sha1 = await digest(att.rawContent, "SHA-1");
        md5hash = await digest(att.rawContent, "MD5");
      } catch { /* skip hashing */ }
    }
    attachments.push({
      filename,
      mimeType: att.contentType.split(";")[0].trim(),
      size: att.rawContent ? att.rawContent.byteLength : new TextEncoder().encode(att.body).length,
      sha256, sha1, md5: md5hash,
      extension: ext,
      isDangerous,
    });
  }

  // Parse addresses
  const fromRaw = decodeEncodedWords(headers["from"] || "");
  const fromParsed = parseEmailAddress(fromRaw);
  const toAddresses = splitAddresses(decodeEncodedWords(headers["to"] || "")).map(parseEmailAddress);
  const ccAddresses = splitAddresses(decodeEncodedWords(headers["cc"] || "")).map(parseEmailAddress);
  const bccAddresses = splitAddresses(decodeEncodedWords(headers["bcc"] || "")).map(parseEmailAddress);

  void getDomainFromEmail;

  const metadata: EmailMetadata = {
    from: fromRaw,
    fromName: fromParsed.name,
    fromAddress: fromParsed.address,
    to: toAddresses.map((a) => a.address).filter(Boolean),
    toAddresses,
    cc: ccAddresses.map((a) => a.address).filter(Boolean),
    bcc: bccAddresses.map((a) => a.address).filter(Boolean),
    replyTo: decodeEncodedWords(headers["reply-to"] || ""),
    returnPath: headers["return-path"] || "",
    subject: decodeEncodedWords(headers["subject"] || ""),
    date: headers["date"] || "",
    messageId: headers["message-id"] || "",
    inReplyTo: headers["in-reply-to"] || "",
    references: headers["references"] || "",
    userAgent: headers["user-agent"] || headers["x-mailer"] || "",
    mimeVersion: headers["mime-version"] || "",
    contentType: headers["content-type"] || "",
    textBody,
    htmlBody,
    rawHeaders: headers,
  };

  return { metadata, attachments };
}
