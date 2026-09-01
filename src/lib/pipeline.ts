// Analysis Pipeline — orchestrates the full forensic analysis
import type { AnalysisResult, ProcessingStage, ThreatIntelResult, GeoLocation } from "./types";
import { parseEML } from "./emlParser";
import { parseReceivedHeaders, detectHeaderAnomalies } from "./headerForensics";
import { analyzeEmailAuth } from "./emailAuth";
import { extractIndicators } from "./indicatorExtractor";
import { ThreatIntelEngine } from "./threatIntel";
import { geolocateIPs } from "./geoip";
import { calculateRisk } from "./riskEngine";
import { generateAIAssessment } from "./aiAnalyzer";
import { buildInvestigationGraph } from "./graphBuilder";
import { saveInvestigation } from "./storage";

export type ProgressCallback = (stage: ProcessingStage, message: string) => void;

function generateInvestigationId(): string {
  const ts = Date.now().toString(36);
  const rand = Math.random().toString(36).slice(2, 8);
  return `inv_${ts}_${rand}`;
}

export async function analyzeEML(
  file: File,
  onProgress?: ProgressCallback,
): Promise<AnalysisResult> {
  const errors: string[] = [];
  const investigationId = generateInvestigationId();

  // Stage 1: Read file
  onProgress?.("uploading", "Reading EML file...");
  const rawText = await file.text();
  onProgress?.("uploading", "File loaded successfully");

  // Stage 2: Parse EML
  onProgress?.("parsing", "Parsing email structure...");
  let metadata, attachments;
  try {
    const parsed = await parseEML(rawText);
    metadata = parsed.metadata;
    attachments = parsed.attachments;
  } catch (err) {
    errors.push(`EML parsing error: ${err instanceof Error ? err.message : String(err)}`);
    throw new Error(`Failed to parse EML file: ${err instanceof Error ? err.message : "unknown error"}`);
  }
  onProgress?.("parsing", "Email parsed successfully");

  // Stage 3: Header forensics
  onProgress?.("header_forensics", "Analyzing email headers and Received chain...");
  const hops = parseReceivedHeaders(metadata.rawHeaders);
  const anomalies = detectHeaderAnomalies(metadata, hops);
  onProgress?.("header_forensics", `Found ${hops.length} mail hops, ${anomalies.length} anomalies`);

  // Stage 4: Email authentication
  onProgress?.("header_forensics", "Checking SPF/DKIM/DMARC...");
  const authentication = analyzeEmailAuth(metadata.rawHeaders);

  // Stage 5: Extract indicators
  onProgress?.("extracting_indicators", "Extracting IOCs (IPs, domains, URLs, hashes)...");
  const indicators = extractIndicators(metadata, attachments, hops);
  onProgress?.("extracting_indicators", `Extracted ${indicators.ips.length} IPs, ${indicators.domains.length} domains, ${indicators.urls.length} URLs, ${indicators.hashes.length} hashes`);

  // Stage 6: Threat intelligence enrichment
  onProgress?.("threat_intelligence", "Checking indicators against threat intelligence...");
  const threatEngine = new ThreatIntelEngine();
  const threatResults: ThreatIntelResult[] = [];
  try {
    const ipPromises = indicators.ips.map((ip) => threatEngine.enrichIP(ip));
    const domainPromises = indicators.domains.map((d) => threatEngine.enrichDomain(d));
    const urlPromises = indicators.urls.map((u) => threatEngine.enrichURL(u));
    const hashPromises = indicators.hashes.map((h) => threatEngine.enrichHash(h));

    const [ipResults, domainResults, urlResults, hashResults] = await Promise.all([
      Promise.all(ipPromises),
      Promise.all(domainPromises),
      Promise.all(urlPromises),
      Promise.all(hashPromises),
    ]);

    threatResults.push(...ipResults, ...domainResults, ...urlResults, ...hashResults);
  } catch (err) {
    errors.push(`Threat intelligence error: ${err instanceof Error ? err.message : String(err)}`);
  }
  onProgress?.("threat_intelligence", `Threat intelligence completed — ${threatResults.filter((t) => t.reputation === "malicious").length} malicious, ${threatResults.filter((t) => t.reputation === "suspicious").length} suspicious`);

  // Attach threat results to indicators
  indicators.ips.forEach((ip) => {
    ip.threat = threatResults.find((t) => t.type === "ip" && t.indicator === ip.address) || null;
  });
  indicators.domains.forEach((d) => {
    d.threat = threatResults.find((t) => t.type === "domain" && t.indicator === d.domain) || null;
  });
  indicators.urls.forEach((u) => {
    u.threat = threatResults.find((t) => t.type === "url" && t.indicator === u.url) || null;
  });
  indicators.hashes.forEach((h) => {
    h.threat = threatResults.find((t) => t.type === "hash" && t.indicator === h.hash) || null;
  });

  // Stage 7: Geolocation
  onProgress?.("geolocation", "Geolocating public IP addresses...");
  let geoLocations: GeoLocation[] = [];
  try {
    geoLocations = await geolocateIPs(indicators.ips);
    // Attach geo to IP indicators
    indicators.ips.forEach((ip) => {
      ip.geo = geoLocations.find((g) => g.ip === ip.address) || null;
    });
  } catch (err) {
    errors.push(`Geolocation error: ${err instanceof Error ? err.message : String(err)}`);
  }
  onProgress?.("geolocation", `Geolocated ${geoLocations.filter((g) => g.success).length} IPs`);

  // Stage 8: Risk analysis
  onProgress?.("risk_analysis", "Calculating threat score...");
  const risk = calculateRisk(metadata, authentication, anomalies, indicators, threatResults, attachments);
  onProgress?.("risk_analysis", `Risk score: ${risk.score}/100 — ${risk.level}`);

  // Stage 9: AI analysis
  onProgress?.("ai_analysis", "Generating AI forensic assessment...");
  const aiAssessment = generateAIAssessment({
    metadata,
    authentication,
    indicators,
    threatResults,
    anomalies,
    risk,
  });
  onProgress?.("ai_analysis", "AI assessment completed");

  // Stage 10: Build investigation graph
  onProgress?.("generating_report", "Building investigation graph and report...");
  const graph = buildInvestigationGraph(metadata, indicators, threatResults, geoLocations, hops);

  const result: AnalysisResult = {
    investigationId,
    filename: file.name,
    uploadedAt: new Date().toISOString(),
    analyzedAt: new Date().toISOString(),
    status: errors.length > 0 ? "partial" : "completed",
    email: metadata,
    headers: hops,
    anomalies,
    authentication,
    indicators,
    threatIntelligence: threatResults,
    geolocation: geoLocations,
    risk,
    aiAssessment,
    graph,
    report: {
      generatedAt: new Date().toISOString(),
      format: "json",
      sections: [
        "Executive Summary", "Email Metadata", "Header Analysis", "Authentication Analysis",
        "IOC Extraction", "Threat Intelligence Findings", "IP Geolocation", "Email Route",
        "Investigation Graph", "Threat Score", "AI Assessment", "Evidence",
        "Analyst Recommendations", "Limitations", "Data Sources",
      ],
    },
    errors,
  };

  onProgress?.("generating_report", "Report generated successfully");

  // Stage 11: Save investigation
  onProgress?.("saving_investigation", "Saving investigation to database...");
  try {
    await saveInvestigation(result);
    onProgress?.("saving_investigation", "Investigation saved successfully");
  } catch (err) {
    errors.push(`Save error: ${err instanceof Error ? err.message : String(err)}`);
    onProgress?.("saving_investigation", "Investigation saved with warnings");
  }

  onProgress?.("completed", "Analysis complete");

  return result;
}
