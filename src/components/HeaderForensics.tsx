import { FileSearch, Server, Clock, AlertTriangle, CheckCircle2, ShieldCheck, ShieldX, ShieldAlert } from "lucide-react";
import type { AnalysisResult } from "@/lib/types";

interface HeaderForensicsProps {
  result: AnalysisResult;
}

export function HeaderForensics({ result }: HeaderForensicsProps) {
  const { headers, anomalies, authentication } = result;

  const authItems = [
    { label: "SPF", value: authentication.spf, detail: authentication.spfDomain },
    { label: "DKIM", value: authentication.dkim, detail: authentication.dkimDomain ? `${authentication.dkimDomain} (s=${authentication.dkimSelector})` : "" },
    { label: "DMARC", value: authentication.dmarc, detail: authentication.dmarcPolicy ? `policy: ${authentication.dmarcPolicy}` : "" },
    { label: "ARC", value: authentication.arc, detail: "" },
  ];

  const authIcon = (val: string) => {
    if (val === "PASS") return <ShieldCheck className="w-4 h-4 text-green-400" />;
    if (val === "FAIL") return <ShieldX className="w-4 h-4 text-red-400" />;
    if (val === "NONE" || val === "UNKNOWN") return <ShieldAlert className="w-4 h-4 text-slate-500" />;
    return <ShieldAlert className="w-4 h-4 text-yellow-400" />;
  };

  const severityColor = (sev: string) => {
    if (sev === "high") return "text-red-400 bg-red-500/10 border-red-500/20";
    if (sev === "medium") return "text-yellow-400 bg-yellow-500/10 border-yellow-500/20";
    if (sev === "low") return "text-slate-400 bg-slate-500/10 border-slate-500/20";
    return "text-blue-400 bg-blue-500/10 border-blue-500/20";
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center">
          <FileSearch className="w-5 h-5 text-cyan-400" />
        </div>
        <div>
          <h2 className="text-xl font-bold text-white">Header Forensics</h2>
          <p className="text-sm text-slate-500">Received chain analysis, authentication, and anomaly detection</p>
        </div>
      </div>

      {/* Authentication */}
      <div className="p-5 rounded-xl bg-slate-800/40 border border-slate-700/50">
        <h3 className="text-white font-semibold mb-4">Email Authentication (SPF / DKIM / DMARC / ARC)</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {authItems.map((item) => (
            <div key={item.label} className="p-3 rounded-lg bg-slate-900/40 border border-slate-700/30">
              <div className="flex items-center gap-2 mb-2">
                {authIcon(item.value)}
                <span className="text-slate-400 text-xs uppercase tracking-wider">{item.label}</span>
              </div>
              <div className={`text-lg font-bold ${
                item.value === "PASS" ? "text-green-400" :
                item.value === "FAIL" ? "text-red-400" :
                item.value === "NONE" || item.value === "UNKNOWN" ? "text-slate-500" : "text-yellow-400"
              }`}>{item.value}</div>
              {item.detail && <div className="text-xs text-slate-500 mt-1 font-mono break-all">{item.detail}</div>}
            </div>
          ))}
        </div>
        {authentication.authDetails && (
          <div className="mt-4 p-3 rounded-lg bg-slate-900/40">
            <div className="text-xs text-slate-500 mb-1">Authentication Details</div>
            <pre className="text-xs text-slate-400 font-mono whitespace-pre-wrap break-all">{authentication.authDetails}</pre>
          </div>
        )}
      </div>

      {/* Mail hop timeline */}
      <div className="p-5 rounded-xl bg-slate-800/40 border border-slate-700/50">
        <h3 className="text-white font-semibold mb-4 flex items-center gap-2">
          <Server className="w-4 h-4 text-cyan-400" /> Mail Hop Timeline ({headers.length} hops)
        </h3>
        {headers.length === 0 ? (
          <p className="text-slate-500 text-sm">No Received headers found in this email.</p>
        ) : (
          <div className="space-y-3">
            {headers.map((hop, idx) => (
              <div key={idx} className="relative pl-8">
                {/* Timeline line */}
                {idx < headers.length - 1 && (
                  <div className="absolute left-3 top-8 bottom-0 w-0.5 bg-slate-700" />
                )}
                <div className={`absolute left-0 top-1.5 w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold ${
                  hop.sourceIp && hop.sourceIp === result.indicators.ips.find((ip) => ip.threat?.reputation === "malicious")?.address
                    ? "bg-red-500/20 text-red-400 border border-red-500/30"
                    : "bg-cyan-500/10 text-cyan-400 border border-cyan-500/20"
                }`}>
                  {idx + 1}
                </div>
                <div className="p-3 rounded-lg bg-slate-900/40 border border-slate-700/30">
                  <div className="flex items-start justify-between gap-2 flex-wrap">
                    <div className="flex items-center gap-2">
                      <Clock className="w-3.5 h-3.5 text-slate-500" />
                      <span className="text-xs text-slate-400">{hop.timestamp || "No timestamp"}</span>
                      {hop.timezone && <span className="text-xs text-slate-600">UTC{hop.timezone}</span>}
                    </div>
                    {hop.protocol && (
                      <span className="text-xs text-slate-500 bg-slate-800 px-2 py-0.5 rounded">{hop.protocol}</span>
                    )}
                  </div>
                  <div className="mt-2 grid grid-cols-1 md:grid-cols-2 gap-2 text-sm">
                    <div>
                      <span className="text-slate-500 text-xs">From:</span>
                      <span className="text-slate-300 font-mono ml-1.5 break-all">{hop.sourceHostname || "N/A"}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 text-xs">By:</span>
                      <span className="text-slate-300 font-mono ml-1.5 break-all">{hop.by || "N/A"}</span>
                    </div>
                    {hop.sourceIp && (
                      <div>
                        <span className="text-slate-500 text-xs">Source IP:</span>
                        <span className={`font-mono ml-1.5 ${
                          result.indicators.ips.find((ip) => ip.address === hop.sourceIp)?.classification === "private"
                            ? "text-yellow-400" : "text-cyan-400"
                        }`}>{hop.sourceIp}</span>
                      </div>
                    )}
                    {hop.forAddr && (
                      <div>
                        <span className="text-slate-500 text-xs">For:</span>
                        <span className="text-slate-300 font-mono ml-1.5">{hop.forAddr}</span>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Anomalies */}
      <div className="p-5 rounded-xl bg-slate-800/40 border border-slate-700/50">
        <h3 className="text-white font-semibold mb-4 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-cyan-400" /> Header Anomalies ({anomalies.length})
        </h3>
        {anomalies.length === 0 ? (
          <div className="flex items-center gap-2 text-sm text-green-400">
            <CheckCircle2 className="w-4 h-4" />
            No header anomalies detected.
          </div>
        ) : (
          <div className="space-y-2">
            {anomalies.map((anomaly, idx) => (
              <div key={idx} className="p-3 rounded-lg bg-slate-900/40 border border-slate-700/30">
                <div className="flex items-start justify-between gap-2">
                  <p className="text-sm text-slate-200">{anomaly.description}</p>
                  <span className={`text-xs font-semibold px-2 py-0.5 rounded border shrink-0 ${severityColor(anomaly.severity)}`}>
                    {anomaly.severity.toUpperCase()}
                  </span>
                </div>
                <p className="text-xs text-slate-500 mt-1.5 break-all font-mono">{anomaly.evidence}</p>
                <div className="text-xs text-slate-600 mt-1">Category: {anomaly.category}</div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
