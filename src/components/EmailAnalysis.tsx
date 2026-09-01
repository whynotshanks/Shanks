import { Mail, User, ArrowRight, Calendar, MessageSquare, AlertTriangle } from "lucide-react";
import type { AnalysisResult } from "@/lib/types";
import { riskBgClass } from "@/lib/uiUtils";

interface EmailAnalysisProps {
  result: AnalysisResult;
}

export function EmailAnalysis({ result }: EmailAnalysisProps) {
  const { email, risk, aiAssessment } = result;

  const fields = [
    { label: "From", value: email.from, mono: true },
    { label: "From Name", value: email.fromName },
    { label: "From Address", value: email.fromAddress, mono: true },
    { label: "To", value: email.to.join(", "), mono: true },
    { label: "CC", value: email.cc.join(", "), mono: true },
    { label: "BCC", value: email.bcc.join(", "), mono: true },
    { label: "Reply-To", value: email.replyTo, mono: true },
    { label: "Return-Path", value: email.returnPath, mono: true },
    { label: "Subject", value: email.subject },
    { label: "Date", value: email.date },
    { label: "Message-ID", value: email.messageId, mono: true },
    { label: "In-Reply-To", value: email.inReplyTo, mono: true },
    { label: "User-Agent", value: email.userAgent },
    { label: "MIME-Version", value: email.mimeVersion },
    { label: "Content-Type", value: email.contentType, mono: true },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center">
          <Mail className="w-5 h-5 text-cyan-400" />
        </div>
        <div>
          <h2 className="text-xl font-bold text-white">Email Analysis</h2>
          <p className="text-sm text-slate-500">Complete metadata and AI forensic assessment</p>
        </div>
      </div>

      {/* Threat badge */}
      <div className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg border ${riskBgClass(risk.level)}`}>
        <AlertTriangle className="w-4 h-4" />
        <span className="font-bold">{risk.level} RISK — Score: {risk.score}/100</span>
      </div>

      {/* Metadata grid */}
      <div className="p-5 rounded-xl bg-slate-800/40 border border-slate-700/50">
        <h3 className="text-white font-semibold mb-4 flex items-center gap-2">
          <User className="w-4 h-4 text-cyan-400" /> Email Metadata
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {fields.map((field) => (
            <div key={field.label} className="p-3 rounded-lg bg-slate-900/40">
              <div className="text-xs text-slate-500 uppercase tracking-wider mb-1">{field.label}</div>
              <div className={`text-sm text-slate-200 break-all ${field.mono ? "font-mono" : ""}`}>
                {field.value || <span className="text-slate-600 italic">N/A</span>}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Sender → Recipient flow */}
      <div className="p-5 rounded-xl bg-slate-800/40 border border-slate-700/50">
        <h3 className="text-white font-semibold mb-4 flex items-center gap-2">
          <ArrowRight className="w-4 h-4 text-cyan-400" /> Email Flow
        </h3>
        <div className="flex items-center gap-4 flex-wrap">
          <div className="flex-1 min-w-[200px] p-3 rounded-lg bg-slate-900/40 border border-slate-700/50">
            <div className="text-xs text-slate-500 mb-1">Sender</div>
            <div className="text-sm text-slate-200 font-mono break-all">{email.fromAddress || "Unknown"}</div>
            {email.fromName && <div className="text-xs text-slate-500 mt-1">{email.fromName}</div>}
          </div>
          <ArrowRight className="w-5 h-5 text-cyan-400 shrink-0" />
          <div className="flex-1 min-w-[200px] p-3 rounded-lg bg-slate-900/40 border border-slate-700/50">
            <div className="text-xs text-slate-500 mb-1">Recipient(s)</div>
            <div className="text-sm text-slate-200 font-mono break-all">{email.to.join(", ") || "Unknown"}</div>
          </div>
        </div>
      </div>

      {/* Body preview */}
      <div className="p-5 rounded-xl bg-slate-800/40 border border-slate-700/50">
        <h3 className="text-white font-semibold mb-4 flex items-center gap-2">
          <MessageSquare className="w-4 h-4 text-cyan-400" /> Email Body (Plain Text)
        </h3>
        <div className="max-h-96 overflow-y-auto p-4 rounded-lg bg-slate-900/60 border border-slate-700/30">
          <pre className="text-sm text-slate-300 whitespace-pre-wrap break-all font-mono">
            {email.textBody || "(no plain text body available)"}
          </pre>
        </div>
      </div>

      {/* AI Assessment */}
      <div className="p-5 rounded-xl bg-slate-800/40 border border-slate-700/50">
        <h3 className="text-white font-semibold mb-4 flex items-center gap-2">
          <div className="w-5 h-5 rounded bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center">
            <span className="text-white text-[10px] font-bold">AI</span>
          </div>
          AI Investigation Assessment
        </h3>
        <div className="space-y-4">
          <div>
            <h4 className="text-cyan-400 text-sm font-semibold mb-1">Executive Summary</h4>
            <p className="text-sm text-slate-300 leading-relaxed">{aiAssessment.executiveSummary}</p>
          </div>
          <div>
            <h4 className="text-cyan-400 text-sm font-semibold mb-1">Why This Email Is Suspicious</h4>
            <p className="text-sm text-slate-300 leading-relaxed">{aiAssessment.whySuspicious}</p>
          </div>
          <div>
            <h4 className="text-cyan-400 text-sm font-semibold mb-1">Key Evidence</h4>
            <ul className="space-y-1">
              {aiAssessment.keyEvidence.map((e, i) => (
                <li key={i} className="text-sm text-slate-300 flex items-start gap-2">
                  <span className="text-cyan-400 shrink-0 mt-0.5">•</span>
                  <span className="break-all">{e}</span>
                </li>
              ))}
            </ul>
          </div>
          <div>
            <h4 className="text-cyan-400 text-sm font-semibold mb-1">Attack Technique</h4>
            <p className="text-sm text-slate-300 leading-relaxed">{aiAssessment.attackTechnique}</p>
          </div>
          <div>
            <h4 className="text-cyan-400 text-sm font-semibold mb-1">Recommended Actions</h4>
            <ul className="space-y-1">
              {aiAssessment.recommendedActions.map((r, i) => (
                <li key={i} className="text-sm text-slate-300 flex items-start gap-2">
                  <span className="text-cyan-400 shrink-0 mt-0.5">•</span>
                  <span>{r}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>

      {/* Limitations */}
      <div className="p-4 rounded-lg bg-orange-500/5 border-l-4 border-orange-500/40">
        <div className="flex items-center gap-2 mb-1">
          <Calendar className="w-4 h-4 text-orange-400" />
          <h4 className="text-orange-400 text-sm font-semibold">Forensic Limitations</h4>
        </div>
        <p className="text-xs text-slate-400 leading-relaxed">{aiAssessment.limitations}</p>
      </div>
    </div>
  );
}
