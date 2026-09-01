// Shared UI helpers — threat level colors, formatting
import type { RiskAssessment, ThreatIntelResult } from "./types";

export function riskColor(level: RiskAssessment["level"]): string {
  switch (level) {
    case "LOW": return "#22c55e";
    case "MEDIUM": return "#eab308";
    case "HIGH": return "#f97316";
    case "CRITICAL": return "#ef4444";
  }
}

export function riskBgClass(level: RiskAssessment["level"]): string {
  switch (level) {
    case "LOW": return "bg-green-500/20 text-green-400 border-green-500/30";
    case "MEDIUM": return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30";
    case "HIGH": return "bg-orange-500/20 text-orange-400 border-orange-500/30";
    case "CRITICAL": return "bg-red-500/20 text-red-400 border-red-500/30";
  }
}

export function reputationColor(rep: ThreatIntelResult["reputation"]): string {
  switch (rep) {
    case "clean": return "text-green-400";
    case "suspicious": return "text-yellow-400";
    case "malicious": return "text-red-400";
    case "unknown": return "text-slate-500";
  }
}

export function authColor(val: string): string {
  if (val === "PASS") return "text-green-400 bg-green-500/10 border-green-500/20";
  if (val === "FAIL") return "text-red-400 bg-red-500/10 border-red-500/20";
  if (val === "NONE" || val === "UNKNOWN") return "text-slate-500 bg-slate-500/10 border-slate-500/20";
  return "text-yellow-400 bg-yellow-500/10 border-yellow-500/20";
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function truncate(str: string, max: number): string {
  if (str.length <= max) return str;
  return str.slice(0, max) + "...";
}
