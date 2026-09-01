import { CheckCircle2, Loader2, Circle, AlertCircle } from "lucide-react";
import type { ProcessingStep } from "@/lib/types";

interface AnalysisProgressProps {
  steps: ProcessingStep[];
}

export function AnalysisProgress({ steps }: AnalysisProgressProps) {
  const currentStep = steps.find((s) => s.status === "active");
  const completedCount = steps.filter((s) => s.status === "done").length;
  const totalCount = steps.length;
  const progress = Math.round((completedCount / totalCount) * 100);

  return (
    <div className="max-w-2xl mx-auto">
      <div className="text-center mb-8">
        <h2 className="text-2xl font-bold text-white mb-2">Analyzing Email...</h2>
        <p className="text-slate-400">
          {currentStep ? currentStep.label : "Processing..."}
        </p>
      </div>

      {/* Progress bar */}
      <div className="mb-8">
        <div className="flex justify-between text-sm text-slate-400 mb-2">
          <span>Progress</span>
          <span>{progress}%</span>
        </div>
        <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
          <div
            className="h-full bg-gradient-to-r from-cyan-500 to-blue-600 rounded-full transition-all duration-500"
            style={{ width: `${progress}%` }}
          />
        </div>
      </div>

      {/* Steps */}
      <div className="space-y-2">
        {steps.map((step) => (
          <div
            key={step.stage}
            className={`flex items-center gap-3 p-3 rounded-lg border transition-all ${
              step.status === "active"
                ? "bg-cyan-500/5 border-cyan-500/20"
                : step.status === "done"
                ? "bg-slate-800/30 border-slate-700/50"
                : step.status === "error"
                ? "bg-red-500/5 border-red-500/20"
                : "bg-slate-800/20 border-slate-800/50"
            }`}
          >
            <div className="shrink-0">
              {step.status === "done" && <CheckCircle2 className="w-5 h-5 text-green-400" />}
              {step.status === "active" && <Loader2 className="w-5 h-5 text-cyan-400 animate-spin" />}
              {step.status === "error" && <AlertCircle className="w-5 h-5 text-red-400" />}
              {step.status === "pending" && <Circle className="w-5 h-5 text-slate-700" />}
            </div>
            <span
              className={`text-sm ${
                step.status === "done" ? "text-slate-400" :
                step.status === "active" ? "text-cyan-400 font-medium" :
                step.status === "error" ? "text-red-400" : "text-slate-600"
              }`}
            >
              {step.label}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
