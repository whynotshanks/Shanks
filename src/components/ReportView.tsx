import { useState } from "react";
import { FileText, Download, FileJson, FileCode, CheckCircle2 } from "lucide-react";
import type { AnalysisResult } from "@/lib/types";
import { generateJSONReport, generateHTMLReport, downloadFile } from "@/lib/reportGenerator";
import { riskBgClass } from "@/lib/uiUtils";

interface ReportViewProps {
  result: AnalysisResult;
}

export function ReportView({ result }: ReportViewProps) {
  const [downloaded, setDownloaded] = useState<string | null>(null);

  const handleDownloadJSON = () => {
    const json = generateJSONReport(result);
    downloadFile(json, `cybroatrix_report_${result.investigationId}.json`, "application/json");
    setDownloaded("json");
    setTimeout(() => setDownloaded(null), 3000);
  };

  const handleDownloadHTML = () => {
    const html = generateHTMLReport(result);
    downloadFile(html, `cybroatrix_report_${result.investigationId}.html`, "text/html");
    setDownloaded("html");
    setTimeout(() => setDownloaded(null), 3000);
  };

  const sections = [
    "Executive Summary",
    "Email Metadata",
    "Header Analysis",
    "Authentication Analysis",
    "IOC Extraction",
    "Threat Intelligence Findings",
    "IP Geolocation",
    "Email Route",
    "Investigation Graph",
    "Threat Score",
    "AI Assessment",
    "Evidence",
    "Analyst Recommendations",
    "Limitations",
    "Data Sources",
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center">
          <FileText className="w-5 h-5 text-cyan-400" />
        </div>
        <div>
          <h2 className="text-xl font-bold text-white">Forensic Report</h2>
          <p className="text-sm text-slate-500">Download the complete investigation report</p>
        </div>
      </div>

      {/* Report summary card */}
      <div className="p-6 rounded-xl bg-slate-800/40 border border-slate-700/50">
        <div className="flex items-start justify-between gap-4 flex-wrap mb-4">
          <div>
            <h3 className="text-white font-semibold text-lg">Investigation Report</h3>
            <p className="text-sm text-slate-500 mt-1">ID: {result.investigationId}</p>
            <p className="text-xs text-slate-600 mt-0.5">Generated: {new Date(result.analyzedAt).toLocaleString()}</p>
          </div>
          <div className={`px-4 py-2 rounded-lg border ${riskBgClass(result.risk.level)}`}>
            <div className="text-2xl font-bold">{result.risk.score}/100</div>
            <div className="text-xs font-semibold">{result.risk.level}</div>
          </div>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-4">
          <div className="p-3 rounded-lg bg-slate-900/40">
            <div className="text-xs text-slate-500">Sender</div>
            <div className="text-sm text-slate-300 font-mono truncate">{result.email.fromAddress || "N/A"}</div>
          </div>
          <div className="p-3 rounded-lg bg-slate-900/40">
            <div className="text-xs text-slate-500">Recipient</div>
            <div className="text-sm text-slate-300 font-mono truncate">{result.email.to[0] || "N/A"}</div>
          </div>
          <div className="p-3 rounded-lg bg-slate-900/40">
            <div className="text-xs text-slate-500">Subject</div>
            <div className="text-sm text-slate-300 truncate">{result.email.subject || "N/A"}</div>
          </div>
          <div className="p-3 rounded-lg bg-slate-900/40">
            <div className="text-xs text-slate-500">File</div>
            <div className="text-sm text-slate-300 truncate">{result.filename}</div>
          </div>
        </div>
      </div>

      {/* Download buttons */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <button
          onClick={handleDownloadJSON}
          className="flex items-center gap-4 p-5 rounded-xl bg-slate-800/40 border border-slate-700/50 hover:border-cyan-500/30 hover:bg-slate-800/60 transition-all text-left group"
        >
          <div className="w-12 h-12 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center shrink-0">
            {downloaded === "json" ? <CheckCircle2 className="w-6 h-6 text-green-400" /> : <FileJson className="w-6 h-6 text-cyan-400" />}
          </div>
          <div className="min-w-0 flex-1">
            <h4 className="text-white font-semibold">JSON Report</h4>
            <p className="text-xs text-slate-500 mt-0.5">Complete structured data — all indicators, threat intel, geolocation, risk factors</p>
          </div>
          <Download className="w-5 h-5 text-slate-600 group-hover:text-cyan-400 transition-colors shrink-0" />
        </button>

        <button
          onClick={handleDownloadHTML}
          className="flex items-center gap-4 p-5 rounded-xl bg-slate-800/40 border border-slate-700/50 hover:border-cyan-500/30 hover:bg-slate-800/60 transition-all text-left group"
        >
          <div className="w-12 h-12 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center shrink-0">
            {downloaded === "html" ? <CheckCircle2 className="w-6 h-6 text-green-400" /> : <FileCode className="w-6 h-6 text-cyan-400" />}
          </div>
          <div className="min-w-0 flex-1">
            <h4 className="text-white font-semibold">HTML Report</h4>
            <p className="text-xs text-slate-500 mt-0.5">Printable forensic report with all sections — open in any browser, save as PDF</p>
          </div>
          <Download className="w-5 h-5 text-slate-600 group-hover:text-cyan-400 transition-colors shrink-0" />
        </button>
      </div>

      {/* Report sections preview */}
      <div className="p-5 rounded-xl bg-slate-800/40 border border-slate-700/50">
        <h3 className="text-white font-semibold mb-3">Report Sections ({sections.length})</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
          {sections.map((section, i) => (
            <div key={i} className="flex items-center gap-2 text-sm text-slate-400 p-2 rounded-lg bg-slate-900/30">
              <span className="text-cyan-500 text-xs font-mono shrink-0">{String(i + 1).padStart(2, "0")}</span>
              <span>{section}</span>
            </div>
          ))}
        </div>
      </div>

      {/* AI Summary preview */}
      <div className="p-5 rounded-xl bg-slate-800/40 border border-slate-700/50">
        <h3 className="text-white font-semibold mb-3">Executive Summary Preview</h3>
        <p className="text-sm text-slate-300 leading-relaxed">{result.aiAssessment.executiveSummary}</p>
        <div className="mt-3 p-3 rounded-lg bg-orange-500/5 border-l-4 border-orange-500/40">
          <p className="text-xs text-slate-400 leading-relaxed">{result.aiAssessment.limitations}</p>
        </div>
      </div>
    </div>
  );
}
