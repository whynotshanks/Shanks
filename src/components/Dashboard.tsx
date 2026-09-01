import { Shield, AlertTriangle, Globe, Link2, FileWarning, Radar, ChevronRight } from "lucide-react";
import type { AnalysisResult } from "@/lib/types";
import { riskBgClass } from "@/lib/uiUtils";
import type { ViewId } from "./Sidebar";

interface DashboardProps {
  result: AnalysisResult;
  onNavigate: (view: ViewId) => void;
}

export function Dashboard({ result, onNavigate }: DashboardProps) {
  const { risk, indicators, anomalies, authentication, aiAssessment } = result;

  const stats = [
    { label: "Threat Score", value: `${risk.score}/100`, sub: risk.level, color: riskBgClass(risk.level) },
    { label: "IPs Found", value: indicators.ips.length, sub: `${indicators.ips.filter((i) => i.classification === "public").length} public`, icon: Globe },
    { label: "Domains", value: indicators.domains.length, sub: `${indicators.domains.filter((d) => d.threat?.reputation === "malicious").length} malicious`, icon: Link2 },
    { label: "URLs", value: indicators.urls.length, sub: `${indicators.urls.filter((u) => u.threat?.reputation === "malicious").length} malicious`, icon: Link2 },
    { label: "Attachments", value: indicators.attachments.length, sub: `${indicators.attachments.filter((a) => a.isDangerous).length} dangerous`, icon: FileWarning },
    { label: "Anomalies", value: anomalies.length, sub: `${anomalies.filter((a) => a.severity === "high").length} high severity`, icon: AlertTriangle },
  ];

  const authBadges = [
    { label: "SPF", value: authentication.spf },
    { label: "DKIM", value: authentication.dkim },
    { label: "DMARC", value: authentication.dmarc },
  ];

  const panels = [
    { id: "analysis" as ViewId, title: "Email Overview", desc: "Sender, recipient, subject, and metadata" },
    { id: "header" as ViewId, title: "Header Forensics", desc: `Received chain, ${anomalies.length} anomalies detected` },
    { id: "geo" as ViewId, title: "Geo-Forensic Map", desc: `${result.geolocation.filter((g) => g.success).length} IPs geolocated` },
    { id: "threat" as ViewId, title: "Threat Intelligence", desc: `${result.threatIntelligence.filter((t) => t.reputation === "malicious").length} malicious indicators` },
    { id: "graph" as ViewId, title: "Investigation Graph", desc: `${result.graph.nodes.length} nodes, ${result.graph.edges.length} relationships` },
    { id: "report" as ViewId, title: "Forensic Report", desc: "Download PDF/JSON/HTML report" },
  ];

  return (
    <div className="space-y-6">
      {/* Top stats */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {stats.map((stat) => (
          <div key={stat.label} className="p-4 rounded-xl bg-slate-800/40 border border-slate-700/50">
            {stat.icon ? (
              <div className="flex items-center justify-between mb-2">
                <span className="text-slate-500 text-xs uppercase tracking-wider">{stat.label}</span>
                <stat.icon className="w-4 h-4 text-slate-600" />
              </div>
            ) : (
              <div className="mb-2">
                <span className="text-slate-500 text-xs uppercase tracking-wider">{stat.label}</span>
              </div>
            )}
            <div className={`text-2xl font-bold ${stat.color ? stat.color : "text-white"}`}>{stat.value}</div>
            <div className="text-xs text-slate-500 mt-1">{stat.sub}</div>
          </div>
        ))}
      </div>

      {/* Email overview + threat assessment */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 p-5 rounded-xl bg-slate-800/40 border border-slate-700/50">
          <div className="flex items-center gap-2 mb-4">
            <Shield className="w-4 h-4 text-cyan-400" />
            <h3 className="text-white font-semibold">Email Overview</h3>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
            <div>
              <span className="text-slate-500">From</span>
              <p className="text-slate-200 font-mono break-all">{result.email.fromAddress || "N/A"}</p>
            </div>
            <div>
              <span className="text-slate-500">To</span>
              <p className="text-slate-200 font-mono break-all">{result.email.to.join(", ") || "N/A"}</p>
            </div>
            <div className="md:col-span-2">
              <span className="text-slate-500">Subject</span>
              <p className="text-slate-200">{result.email.subject || "(no subject)"}</p>
            </div>
            <div>
              <span className="text-slate-500">Date</span>
              <p className="text-slate-200">{result.email.date || "N/A"}</p>
            </div>
            <div>
              <span className="text-slate-500">Reply-To</span>
              <p className="text-slate-200 font-mono break-all">{result.email.replyTo || "N/A"}</p>
            </div>
          </div>
        </div>

        <div className="p-5 rounded-xl bg-slate-800/40 border border-slate-700/50">
          <div className="flex items-center gap-2 mb-4">
            <Radar className="w-4 h-4 text-cyan-400" />
            <h3 className="text-white font-semibold">Threat Assessment</h3>
          </div>
          <div className="text-center py-3">
            <div className={`inline-block px-4 py-1.5 rounded-lg text-lg font-bold border ${riskBgClass(risk.level)}`}>
              {risk.level}
            </div>
            <div className="text-4xl font-bold text-white mt-3">{risk.score}<span className="text-slate-600 text-xl">/100</span></div>
            <div className="text-xs text-slate-500 mt-1">Confidence: {Math.round(risk.confidence * 100)}%</div>
          </div>
          <div className="flex justify-center gap-2 mt-3">
            {authBadges.map((badge) => (
              <div key={badge.label} className="text-center">
                <div className="text-[10px] text-slate-500 uppercase tracking-wider">{badge.label}</div>
                <div className={`text-xs font-bold px-2 py-0.5 rounded mt-1 ${
                  badge.value === "PASS" ? "text-green-400 bg-green-500/10" :
                  badge.value === "FAIL" ? "text-red-400 bg-red-500/10" :
                  "text-slate-500 bg-slate-500/10"
                }`}>{badge.value}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Risk factors */}
      {risk.factors.length > 0 && (
        <div className="p-5 rounded-xl bg-slate-800/40 border border-slate-700/50">
          <h3 className="text-white font-semibold mb-3">Top Risk Factors ({risk.factors.length})</h3>
          <div className="space-y-2">
            {risk.factors.slice(0, 5).map((factor, i) => (
              <div key={i} className="flex items-start gap-3 p-2.5 rounded-lg bg-slate-900/50">
                <span className={`text-sm font-bold shrink-0 ${
                  factor.points >= 25 ? "text-red-400" : factor.points >= 15 ? "text-orange-400" : "text-yellow-400"
                }`}>+{factor.points}</span>
                <div className="min-w-0">
                  <p className="text-sm text-slate-300">{factor.name}</p>
                  <p className="text-xs text-slate-500 mt-0.5 break-all">{factor.evidence}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* AI Summary */}
      <div className="p-5 rounded-xl bg-slate-800/40 border border-slate-700/50">
        <div className="flex items-center gap-2 mb-3">
          <div className="w-6 h-6 rounded bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center">
            <span className="text-white text-xs font-bold">AI</span>
          </div>
          <h3 className="text-white font-semibold">AI Investigation Summary</h3>
        </div>
        <p className="text-sm text-slate-300 leading-relaxed">{aiAssessment.executiveSummary}</p>
        <p className="text-xs text-slate-500 mt-3">{aiAssessment.confidence}</p>
      </div>

      {/* Navigation panels */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {panels.map((panel) => (
          <button
            key={panel.id}
            onClick={() => onNavigate(panel.id)}
            className="flex items-center gap-3 p-4 rounded-xl bg-slate-800/40 border border-slate-700/50 hover:border-cyan-500/30 hover:bg-slate-800/60 transition-all text-left group"
          >
            <div className="min-w-0 flex-1">
              <p className="text-white font-medium text-sm">{panel.title}</p>
              <p className="text-xs text-slate-500 mt-0.5">{panel.desc}</p>
            </div>
            <ChevronRight className="w-4 h-4 text-slate-600 group-hover:text-cyan-400 transition-colors shrink-0" />
          </button>
        ))}
      </div>
    </div>
  );
}
