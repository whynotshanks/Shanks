// Investigation Graph Builder — constructs nodes and edges from analysis results
import type { InvestigationGraph, GraphNode, GraphEdge, EmailMetadata, Indicators, ThreatIntelResult, GeoLocation, ReceivedHop } from "./types";

let nodeCounter = 0;
function nodeId(): string {
  return `n${++nodeCounter}`;
}

function riskFromScore(score: number): "high" | "medium" | "low" | "none" {
  if (score >= 70) return "high";
  if (score >= 40) return "medium";
  if (score >= 15) return "low";
  return "none";
}

export function buildInvestigationGraph(
  metadata: EmailMetadata,
  indicators: Indicators,
  threatResults: ThreatIntelResult[],
  geoLocations: GeoLocation[],
  hops: ReceivedHop[],
): InvestigationGraph {
  nodeCounter = 0;
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const nodeMap = new Map<string, string>(); // key -> nodeId

  function addNode(key: string, label: string, type: string, risk?: "high" | "medium" | "low" | "none"): string {
    if (nodeMap.has(key)) return nodeMap.get(key)!;
    const id = nodeId();
    nodes.push({ id, label, type, risk });
    nodeMap.set(key, id);
    return id;
  }

  function addEdge(source: string, target: string, label: string) {
    edges.push({ source, target, label });
  }

  // Email node
  const emailId = addNode("email", `Email: ${metadata.subject?.slice(0, 30) || "(no subject)"}`, "email");

  // Sender
  const senderId = addNode(`sender_${metadata.fromAddress}`, metadata.fromAddress || "Unknown Sender", "sender");
  addEdge(emailId, senderId, "SENT_BY");

  // Recipients
  for (const toAddr of metadata.to) {
    const recipId = addNode(`recip_${toAddr}`, toAddr, "recipient");
    addEdge(emailId, recipId, "SENT_TO");
  }

  // Sender domain
  const fromDomain = metadata.fromAddress.split("@")[1]?.toLowerCase();
  if (fromDomain) {
    const domainId = addNode(`domain_${fromDomain}`, fromDomain, "domain");
    addEdge(senderId, domainId, "USES_DOMAIN");

    // Check threat for this domain
    const domainThreat = threatResults.find((t) => t.type === "domain" && t.indicator === fromDomain);
    if (domainThreat) {
      const dNode = nodes.find((n) => n.id === domainId);
      if (dNode) dNode.risk = riskFromScore(domainThreat.score);
    }
  }

  // Reply-To if mismatched
  if (metadata.replyTo) {
    const replyAddr = metadata.replyTo.replace(/[<>]/g, "").trim();
    if (replyAddr !== metadata.fromAddress) {
      const replyId = addNode(`replyto_${replyAddr}`, replyAddr, "sender");
      addEdge(emailId, replyId, "REPLY_TO");
    }
  }

  // IPs from received hops + indicators
  const publicIPs = indicators.ips.filter((ip) => ip.classification === "public");
  for (const ip of publicIPs) {
    const ipId = addNode(`ip_${ip.address}`, ip.address, "ip");
    addEdge(emailId, ipId, "ROUTED_THROUGH");

    // Find threat
    const ipThreat = threatResults.find((t) => t.type === "ip" && t.indicator === ip.address);
    if (ipThreat) {
      const ipNode = nodes.find((n) => n.id === ipId);
      if (ipNode) ipNode.risk = riskFromScore(ipThreat.score);
    }

    // Find geo
    const geo = geoLocations.find((g) => g.ip === ip.address && g.success);
    if (geo) {
      const geoLabel = `${geo.city}, ${geo.country}`;
      const geoId = addNode(`geo_${geo.ip}`, geoLabel, "location");
      addEdge(ipId, geoId, "LOCATED_IN");

      if (geo.asn) {
        const asnId = addNode(`asn_${geo.asn}`, geo.asn, "asn");
        addEdge(ipId, asnId, "PART_OF_ASN");
      }
    }
  }

  // URLs
  for (const url of indicators.urls) {
    const urlId = addNode(`url_${url.url}`, url.url.slice(0, 50), "url");
    addEdge(emailId, urlId, "CONTAINS_URL");

    const urlThreat = threatResults.find((t) => t.type === "url" && t.indicator === url.url);
    if (urlThreat) {
      const urlNode = nodes.find((n) => n.id === urlId);
      if (urlNode) urlNode.risk = riskFromScore(urlThreat.score);
    }

    // Link URL to its domain
    if (url.domain) {
      const domainId = addNode(`domain_${url.domain}`, url.domain, "domain");
      addEdge(urlId, domainId, "RESOLVES_TO");
    }
  }

  // Attachments and hashes
  for (const att of indicators.attachments) {
    const attId = addNode(`att_${att.filename}`, att.filename, "attachment");
    addEdge(emailId, attId, "CONTAINS");
    if (att.isDangerous) {
      const attNode = nodes.find((n) => n.id === attId);
      if (attNode) attNode.risk = "high";
    }

    if (att.sha256) {
      const hashId = addNode(`hash_${att.sha256}`, `${att.sha256.slice(0, 16)}...`, "hash");
      addEdge(attId, hashId, "HASH_OF");

      const hashThreat = threatResults.find((t) => t.type === "hash" && t.indicator === att.sha256);
      if (hashThreat) {
        const hashNode = nodes.find((n) => n.id === hashId);
        if (hashNode) hashNode.risk = riskFromScore(hashThreat.score);
      }
    }
  }

  // Domains from indicators
  for (const domain of indicators.domains) {
    const domainId = addNode(`domain_${domain.domain}`, domain.domain, "domain");
    const domainThreat = threatResults.find((t) => t.type === "domain" && t.indicator === domain.domain);
    if (domainThreat) {
      const dNode = nodes.find((n) => n.id === domainId);
      if (dNode) dNode.risk = riskFromScore(domainThreat.score);
    }
  }

  return { nodes, edges };
}
