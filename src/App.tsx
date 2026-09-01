import { useCallback, useState } from "react";
import { Shield, Upload } from "lucide-react";
import { Sidebar, type ViewId } from "@/components/Sidebar";
import { UploadZone } from "@/components/UploadZone";
import { AnalysisProgress } from "@/components/AnalysisProgress";
import { Dashboard } from "@/components/Dashboard";
import { EmailAnalysis } from "@/components/EmailAnalysis";
import { HeaderForensics } from "@/components/HeaderForensics";
import { GeoMap } from "@/components/GeoMap";
import { ThreatIntelView } from "@/components/ThreatIntelView";
import { InvestigationGraph } from "@/components/InvestigationGraph";
import { ReportView } from "@/components/ReportView";
import { HistoryView } from "@/components/HistoryView";
import { analyzeEML } from "@/lib/pipeline";
import type { AnalysisResult, ProcessingStep, ProcessingStage } from "@/lib/types";

const INITIAL_STEPS: ProcessingStep[] = [
  { stage: "uploading", label: "Uploading EML file", status: "pending" },
  { stage: "parsing", label: "Parsing email structure", status: "pending" },
  { stage: "header_forensics", label: "Analyzing email headers & Received chain", status: "pending" },
  { stage: "extracting_indicators", label: "Extracting IOCs (IPs, domains, URLs, hashes)", status: "pending" },
  { stage: "threat_intelligence", label: "Checking threat intelligence databases", status: "pending" },
  { stage: "geolocation", label: "Geolocating public IP addresses", status: "pending" },
  { stage: "risk_analysis", label: "Calculating threat score", status: "pending" },
  { stage: "ai_analysis", label: "AI forensic assessment", status: "pending" },
  { stage: "generating_report", label: "Building investigation graph & report", status: "pending" },
  { stage: "saving_investigation", label: "Saving investigation to database", status: "pending" },
];

function App() {
  const [activeView, setActiveView] = useState<ViewId>("upload");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [steps, setSteps] = useState<ProcessingStep[]>(INITIAL_STEPS);
  const [historyRefresh, setHistoryRefresh] = useState(0);

  const handleFileSelect = useCallback((file: File) => {
    setSelectedFile(file);
    setError(null);
  }, []);

  const handleAnalyze = useCallback(async () => {
    if (!selectedFile) return;
    setIsAnalyzing(true);
    setError(null);
    setResult(null);
    setSteps(INITIAL_STEPS.map((s) => ({ ...s, status: "pending" })));

    const stageOrder: ProcessingStage[] = [
      "uploading", "parsing", "header_forensics", "extracting_indicators",
      "threat_intelligence", "geolocation", "risk_analysis", "ai_analysis",
      "generating_report", "saving_investigation",
    ];

    try {
      const analysisResult = await analyzeEML(selectedFile, (stage, _message) => {
        const stageIdx = stageOrder.indexOf(stage);
        setSteps((prev) =>
          prev.map((s, i) => {
            if (i < stageIdx) return { ...s, status: "done" };
            if (i === stageIdx) return { ...s, status: "active" };
            return s;
          })
        );
      });

      // Mark all steps as done
      setSteps((prev) => prev.map((s) => ({ ...s, status: "done" })));
      setResult(analysisResult);
      setActiveView("dashboard");
      setHistoryRefresh((n) => n + 1);
    } catch (err) {
      setError(err instanceof Error ? err.message : "An unexpected error occurred during analysis");
      setSteps((prev) => prev.map((s) => (s.status === "active" ? { ...s, status: "error" } : s)));
    } finally {
      setIsAnalyzing(false);
    }
  }, [selectedFile]);

  const handleSelectInvestigation = useCallback((investigationResult: AnalysisResult) => {
    setResult(investigationResult);
    setActiveView("dashboard");
  }, []);

  const handleNavigate = useCallback((view: ViewId) => {
    setActiveView(view);
    setError(null);
  }, []);

  const hasResult = result !== null;

  return (
    <div className="min-h-screen bg-slate-950 flex">
      <Sidebar
        activeView={activeView}
        onNavigate={handleNavigate}
        hasResult={hasResult}
        threatScore={result?.risk.score ?? 0}
        threatLevel={result?.risk.level ?? "LOW"}
      />

      <main className="flex-1 overflow-y-auto h-screen">
        {/* Top bar */}
        <header className="sticky top-0 z-10 bg-slate-900/80 backdrop-blur-sm border-b border-slate-800 px-6 py-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4 text-cyan-400" />
              <span className="text-slate-400 text-sm font-medium">
                {activeView === "upload" && "Upload EML File"}
                {activeView === "dashboard" && "Investigation Dashboard"}
                {activeView === "analysis" && "Email Analysis"}
                {activeView === "header" && "Header Forensics"}
                {activeView === "geo" && "Geo-Forensic Map"}
                {activeView === "threat" && "Threat Intelligence"}
                {activeView === "graph" && "Investigation Graph"}
                {activeView === "report" && "Forensic Report"}
                {activeView === "history" && "Investigation History"}
              </span>
            </div>
            {result && (
              <div className="flex items-center gap-3 text-xs text-slate-500">
                <span className="font-mono">{result.investigationId.slice(0, 25)}</span>
                <span className="text-slate-700">|</span>
                <span>{result.filename}</span>
              </div>
            )}
          </div>
        </header>

        <div className="p-6">
          {activeView === "upload" && (
            isAnalyzing ? (
              <AnalysisProgress steps={steps} />
            ) : (
              <UploadZone
                onFileSelect={handleFileSelect}
                onAnalyze={handleAnalyze}
                selectedFile={selectedFile}
                isAnalyzing={isAnalyzing}
                error={error}
              />
            )
          )}

          {activeView === "dashboard" && result && (
            <Dashboard result={result} onNavigate={handleNavigate} />
          )}

          {activeView === "analysis" && result && (
            <EmailAnalysis result={result} />
          )}

          {activeView === "header" && result && (
            <HeaderForensics result={result} />
          )}

          {activeView === "geo" && result && (
            <GeoMap result={result} />
          )}

          {activeView === "threat" && result && (
            <ThreatIntelView result={result} />
          )}

          {activeView === "graph" && result && (
            <InvestigationGraph result={result} />
          )}

          {activeView === "report" && result && (
            <ReportView result={result} />
          )}

          {activeView === "history" && (
            <HistoryView
              onSelectInvestigation={handleSelectInvestigation}
              refreshTrigger={historyRefresh}
            />
          )}

          {/* Empty state for result-dependent views when no result */}
          {!result && !isAnalyzing && activeView !== "upload" && activeView !== "history" && (
            <div className="text-center py-20">
              <Upload className="w-12 h-12 text-slate-700 mx-auto mb-4" />
              <p className="text-slate-500 mb-2">No analysis results to display yet</p>
              <button
                onClick={() => handleNavigate("upload")}
                className="text-cyan-400 text-sm hover:underline"
              >
                Upload an EML file to begin analysis
              </button>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}

export default App;
