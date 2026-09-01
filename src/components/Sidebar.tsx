import { Shield, Upload, FileSearch, MapPin, Radar, Network, FileText, History, Mail, Globe } from "lucide-react";

export type ViewId = "dashboard" | "upload" | "analysis" | "header" | "geo" | "threat" | "graph" | "report" | "history";

interface SidebarProps {
  activeView: ViewId;
  onNavigate: (view: ViewId) => void;
  hasResult: boolean;
  threatScore: number;
  threatLevel: string;
}

const navItems: { id: ViewId; label: string; icon: typeof Shield; requiresResult?: boolean }[] = [
  { id: "dashboard", label: "Dashboard", icon: Shield },
  { id: "upload", label: "Upload EML", icon: Upload },
  { id: "analysis", label: "Email Analysis", icon: Mail, requiresResult: true },
  { id: "header", label: "Header Forensics", icon: FileSearch, requiresResult: true },
  { id: "geo", label: "Geo-Forensics", icon: MapPin, requiresResult: true },
  { id: "threat", label: "Threat Intelligence", icon: Radar, requiresResult: true },
  { id: "graph", label: "Investigation Graph", icon: Network, requiresResult: true },
  { id: "report", label: "Reports", icon: FileText, requiresResult: true },
  { id: "history", label: "Investigation History", icon: History },
];

export function Sidebar({ activeView, onNavigate, hasResult, threatScore, threatLevel }: SidebarProps) {
  const levelColor = threatLevel === "CRITICAL" ? "text-red-400" :
    threatLevel === "HIGH" ? "text-orange-400" :
    threatLevel === "MEDIUM" ? "text-yellow-400" : "text-green-400";

  return (
    <aside className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col h-screen sticky top-0 shrink-0">
      {/* Brand */}
      <div className="p-5 border-b border-slate-800">
        <div className="flex items-center gap-2.5">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-white font-bold text-sm tracking-wide">CybroatriX</h1>
            <p className="text-slate-500 text-[10px] tracking-wider uppercase">Email Forensics AI</p>
          </div>
        </div>
        <p className="text-slate-600 text-[10px] mt-2 tracking-wide">Connect &bull; Innovate &bull; Empower</p>
      </div>

      {/* Threat score badge */}
      {hasResult && (
        <div className="mx-4 mt-4 p-3 rounded-lg bg-slate-800/50 border border-slate-700">
          <div className="flex items-center justify-between mb-1">
            <span className="text-slate-400 text-[10px] uppercase tracking-wider">Threat Score</span>
            <Globe className="w-3 h-3 text-slate-500" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className={`text-2xl font-bold ${levelColor}`}>{threatScore}</span>
            <span className="text-slate-500 text-sm">/ 100</span>
          </div>
          <div className={`text-xs font-semibold ${levelColor} mt-0.5`}>{threatLevel}</div>
        </div>
      )}

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-4 px-3 space-y-0.5">
        {navItems.map((item) => {
          const disabled = item.requiresResult && !hasResult;
          const active = activeView === item.id;
          return (
            <button
              key={item.id}
              onClick={() => !disabled && onNavigate(item.id)}
              disabled={disabled}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all ${
                active
                  ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/20"
                  : disabled
                  ? "text-slate-700 cursor-not-allowed"
                  : "text-slate-400 hover:bg-slate-800/50 hover:text-slate-200"
              }`}
            >
              <item.icon className="w-4 h-4 shrink-0" />
              <span className="truncate">{item.label}</span>
              {active && <div className="ml-auto w-1.5 h-1.5 rounded-full bg-cyan-400" />}
            </button>
          );
        })}
      </nav>

      <div className="p-4 border-t border-slate-800">
        <p className="text-slate-600 text-[10px] text-center">SIH26106 &bull; AI-Powered Email Forensics</p>
      </div>
    </aside>
  );
}
