import { Radar, Globe, Link2, FileWarning, Hash } from "lucide-react";
import type { AnalysisResult, ThreatIntelResult } from "@/lib/types";
import { reputationColor } from "@/lib/uiUtils";

interface ThreatIntelViewProps {
  result: AnalysisResult;
}

export function ThreatIntelView({ result }: ThreatIntelViewProps) {
  const { threatIntelligence, indicators } = result;

  const malicious = threatIntelligence.filter((t) => t.reputation === "malicious");
  const suspicious = threatIntelligence.filter((t) => t.reputation === "suspicious");
  const clean = threatIntelligence.filter((t) => t.reputation === "clean");
  const unknown = threatIntelligence.filter((t) => t.reputation === "unknown");

  const byType = (type: ThreatIntelResult["type"]) => threatIntelligence.filter((t) => t.type === type);

  const sections = [
    { type: "ip" as const, label: "IP Addresses", icon: Globe, items: byType("ip") },
    { type: "domain" as const, label: "Domains", icon: Link2, items: byType("domain") },
    { type: "url" as const, label: "URLs", icon: Link2, items: byType("url") },
    { type: "hash" as const, label: "File Hashes", icon: Hash, items: byType("hash") },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center">
          <Radar className="w-5 h-5 text-cyan-400" />
        </div>
        <div>
          <h2 className="text-xl font-bold text-white">Threat Intelligence</h2>
          <p className="text-sm text-slate-500">IOC enrichment from threat intelligence providers</p>
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/20">
          <div className="text-red-400 text-2xl font-bold">{malicious.length}</div>
          <div className="text-slate-400 text-xs mt-1">Malicious</div>
        </div>
        <div className="p-4 rounded-xl bg-yellow-500/10 border border-yellow-500/20">
          <div className="text-yellow-400 text-2xl font-bold">{suspicious.length}</div>
          <div className="text-slate-400 text-xs mt-1">Suspicious</div>
        </div>
        <div className="p-4 rounded-xl bg-green-500/10 border border-green-500/20">
          <div className="text-green-400 text-2xl font-bold">{clean.length}</div>
          <div className="text-slate-400 text-xs mt-1">Clean</div>
        </div>
        <div className="p-4 rounded-xl bg-slate-700/20 border border-slate-700/40">
          <div className="text-slate-500 text-2xl font-bold">{unknown.length}</div>
          <div className="text-slate-400 text-xs mt-1">Unknown</div>
        </div>
      </div>

      {/* IOC sections by type */}
      {sections.map((section) => (
        <div key={section.type} className="p-5 rounded-xl bg-slate-800/40 border border-slate-700/50">
          <h3 className="text-white font-semibold mb-3 flex items-center gap-2">
            <section.icon className="w-4 h-4 text-cyan-400" />
            {section.label} ({section.items.length})
          </h3>
          {section.items.length === 0 ? (
            <p className="text-slate-500 text-sm">No {section.label.toLowerCase()} found.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-slate-500 text-xs uppercase tracking-wider border-b border-slate-700">
                    <th className="pb-2 pr-4">Indicator</th>
                    <th className="pb-2 pr-4">Reputation</th>
                    <th className="pb-2 pr-4">Score</th>
                    <th className="pb-2 pr-4">Detections</th>
                    <th className="pb-2 pr-4">Details</th>
                    <th className="pb-2">Source</th>
                  </tr>
                </thead>
                <tbody>
                  {section.items.map((item, idx) => (
                    <tr key={idx} className="border-b border-slate-800/50">
                      <td className="py-2.5 pr-4 font-mono text-cyan-400 break-all max-w-[200px]">{item.indicator}</td>
                      <td className={`py-2.5 pr-4 font-semibold ${reputationColor(item.reputation)}`}>
                        {item.reputation.toUpperCase()}
                      </td>
                      <td className="py-2.5 pr-4 text-slate-300">{item.score}</td>
                      <td className="py-2.5 pr-4 text-slate-300">{item.detections}</td>
                      <td className="py-2.5 pr-4 text-slate-400 text-xs break-all max-w-[250px]">{item.details}</td>
                      <td className="py-2.5 text-slate-500 text-xs">{item.provider}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      ))}

      {/* Attachments */}
      {indicators.attachments.length > 0 && (
        <div className="p-5 rounded-xl bg-slate-800/40 border border-slate-700/50">
          <h3 className="text-white font-semibold mb-3 flex items-center gap-2">
            <FileWarning className="w-4 h-4 text-cyan-400" /> Attachments ({indicators.attachments.length})
          </h3>
          <div className="space-y-2">
            {indicators.attachments.map((att, idx) => (
              <div key={idx} className="p-3 rounded-lg bg-slate-900/40 border border-slate-700/30">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <span className="text-slate-200 font-mono text-sm">{att.filename}</span>
                    {att.isDangerous && (
                      <span className="ml-2 text-xs text-red-400 bg-red-500/10 px-2 py-0.5 rounded">DANGEROUS</span>
                    )}
                  </div>
                  <span className="text-xs text-slate-500 shrink-0">{att.mimeType} • {att.size} B</span>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-2 mt-2 text-xs">
                  {att.md5 && <div><span className="text-slate-600">MD5:</span> <span className="text-slate-400 font-mono break-all">{att.md5}</span></div>}
                  {att.sha1 && <div><span className="text-slate-600">SHA-1:</span> <span className="text-slate-400 font-mono break-all">{att.sha1}</span></div>}
                  {att.sha256 && <div><span className="text-slate-600">SHA-256:</span> <span className="text-slate-400 font-mono break-all">{att.sha256}</span></div>}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
