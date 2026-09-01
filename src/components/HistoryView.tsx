import { useEffect, useState } from "react";
import { History, Trash2, Eye, Search, AlertCircle, Loader2 } from "lucide-react";
import type { AnalysisResult } from "@/lib/types";
import { listInvestigations, deleteInvestigation, type InvestigationRecord } from "@/lib/storage";
import { riskBgClass } from "@/lib/uiUtils";

interface HistoryViewProps {
  onSelectInvestigation: (result: AnalysisResult) => void;
  refreshTrigger: number;
}

export function HistoryView({ onSelectInvestigation, refreshTrigger }: HistoryViewProps) {
  const [records, setRecords] = useState<InvestigationRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [levelFilter, setLevelFilter] = useState("ALL");

  useEffect(() => {
    loadHistory();
  }, [refreshTrigger]);

  const loadHistory = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await listInvestigations();
      setRecords(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load investigation history");
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await deleteInvestigation(id);
      setRecords((prev) => prev.filter((r) => r.id !== id));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete investigation");
    }
  };

  const handleView = (record: InvestigationRecord) => {
    if (record.result_data) {
      onSelectInvestigation(record.result_data);
    }
  };

  const filtered = records.filter((r) => {
    const matchesSearch = !search ||
      r.sender.toLowerCase().includes(search.toLowerCase()) ||
      r.subject.toLowerCase().includes(search.toLowerCase()) ||
      r.filename.toLowerCase().includes(search.toLowerCase()) ||
      r.id.toLowerCase().includes(search.toLowerCase());
    const matchesLevel = levelFilter === "ALL" || r.threat_level === levelFilter;
    return matchesSearch && matchesLevel;
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center">
          <History className="w-5 h-5 text-cyan-400" />
        </div>
        <div>
          <h2 className="text-xl font-bold text-white">Investigation History</h2>
          <p className="text-sm text-slate-500">Browse, reopen, or delete past investigations</p>
        </div>
      </div>

      {/* Filters */}
      <div className="flex gap-3 flex-wrap">
        <div className="flex-1 min-w-[200px] relative">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by sender, subject, filename, or ID..."
            className="w-full pl-10 pr-4 py-2.5 rounded-lg bg-slate-800/60 border border-slate-700/50 text-slate-200 text-sm placeholder-slate-600 focus:border-cyan-500/40 focus:outline-none"
          />
        </div>
        <select
          value={levelFilter}
          onChange={(e) => setLevelFilter(e.target.value)}
          className="px-4 py-2.5 rounded-lg bg-slate-800/60 border border-slate-700/50 text-slate-200 text-sm focus:border-cyan-500/40 focus:outline-none"
        >
          <option value="ALL">All Levels</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
      </div>

      {/* Error */}
      {error && (
        <div className="flex items-center gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Loading */}
      {loading && (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="w-6 h-6 text-cyan-400 animate-spin" />
          <span className="text-slate-400 ml-2">Loading investigations...</span>
        </div>
      )}

      {/* Empty state */}
      {!loading && filtered.length === 0 && (
        <div className="text-center py-12">
          <History className="w-12 h-12 text-slate-700 mx-auto mb-3" />
          <p className="text-slate-500">No investigations found. Upload an EML file to begin.</p>
        </div>
      )}

      {/* Table */}
      {!loading && filtered.length > 0 && (
        <div className="overflow-x-auto rounded-xl border border-slate-700/50">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-slate-800/60 text-left text-slate-500 text-xs uppercase tracking-wider">
                <th className="px-4 py-3">Investigation ID</th>
                <th className="px-4 py-3">Date</th>
                <th className="px-4 py-3">File</th>
                <th className="px-4 py-3">Sender</th>
                <th className="px-4 py-3">Subject</th>
                <th className="px-4 py-3">Risk</th>
                <th className="px-4 py-3">Score</th>
                <th className="px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((record) => (
                <tr key={record.id} className="border-t border-slate-800/50 hover:bg-slate-800/30">
                  <td className="px-4 py-3 font-mono text-xs text-cyan-400">{record.id.slice(0, 20)}...</td>
                  <td className="px-4 py-3 text-slate-400 text-xs">
                    {record.created_at ? new Date(record.created_at).toLocaleDateString() : "N/A"}
                  </td>
                  <td className="px-4 py-3 text-slate-300 text-xs truncate max-w-[120px]">{record.filename}</td>
                  <td className="px-4 py-3 text-slate-300 text-xs font-mono truncate max-w-[150px]">{record.sender || "N/A"}</td>
                  <td className="px-4 py-3 text-slate-300 text-xs truncate max-w-[200px]">{record.subject || "N/A"}</td>
                  <td className="px-4 py-3">
                    <span className={`text-xs font-semibold px-2 py-0.5 rounded border ${riskBgClass(record.threat_level as "LOW" | "MEDIUM" | "HIGH" | "CRITICAL")}`}>
                      {record.threat_level}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-slate-200 font-bold">{record.threat_score}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1.5">
                      <button
                        onClick={() => handleView(record)}
                        className="p-1.5 rounded text-slate-400 hover:text-cyan-400 hover:bg-slate-700/40 transition-colors"
                        title="View investigation"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => handleDelete(record.id)}
                        className="p-1.5 rounded text-slate-400 hover:text-red-400 hover:bg-slate-700/40 transition-colors"
                        title="Delete investigation"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
