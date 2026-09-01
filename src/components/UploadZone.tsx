import { useCallback, useRef, useState } from "react";
import { UploadCloud, FileCheck2, AlertCircle, Loader2 } from "lucide-react";

interface UploadZoneProps {
  onFileSelect: (file: File) => void;
  onAnalyze: () => void;
  selectedFile: File | null;
  isAnalyzing: boolean;
  error: string | null;
}

export function UploadZone({ onFileSelect, onAnalyze, selectedFile, isAnalyzing, error }: UploadZoneProps) {
  const [isDragging, setIsDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) validateAndSelect(file);
  }, []);

  const validateAndSelect = (file: File) => {
    const name = file.name.toLowerCase();
    if (!name.endsWith(".eml")) {
      return;
    }
    onFileSelect(file);
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) validateAndSelect(file);
  };

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  return (
    <div className="max-w-3xl mx-auto">
      <div className="text-center mb-8">
        <h2 className="text-2xl font-bold text-white mb-2">Upload Email for Forensic Analysis</h2>
        <p className="text-slate-400">Upload an .EML file to begin a complete forensic investigation</p>
      </div>

      {/* Drop zone */}
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={() => !isAnalyzing && inputRef.current?.click()}
        className={`relative border-2 border-dashed rounded-2xl p-12 text-center cursor-pointer transition-all duration-300 ${
          isDragging
            ? "border-cyan-400 bg-cyan-500/10 scale-[1.01]"
            : selectedFile
            ? "border-slate-700 bg-slate-800/30"
            : "border-slate-700 bg-slate-800/20 hover:border-cyan-500/50 hover:bg-slate-800/40"
        }`}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".eml"
          onChange={handleInputChange}
          className="hidden"
          disabled={isAnalyzing}
        />

        {!selectedFile ? (
          <div className="space-y-4">
            <div className="w-20 h-20 mx-auto rounded-2xl bg-slate-800 flex items-center justify-center border border-slate-700">
              <UploadCloud className="w-10 h-10 text-cyan-400" />
            </div>
            <div>
              <p className="text-lg font-semibold text-white">Drag &amp; Drop your .EML file</p>
              <p className="text-slate-500 text-sm mt-1">or</p>
            </div>
            <button
              type="button"
              className="px-6 py-2.5 bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 rounded-lg font-medium text-sm hover:bg-cyan-500/20 transition-colors"
            >
              Select EML File
            </button>
            <p className="text-slate-600 text-xs mt-2">Supported format: .eml only</p>
          </div>
        ) : (
          <div className="space-y-3">
            <div className="w-16 h-16 mx-auto rounded-2xl bg-green-500/10 border border-green-500/20 flex items-center justify-center">
              <FileCheck2 className="w-8 h-8 text-green-400" />
            </div>
            <div>
              <p className="text-white font-semibold text-lg">{selectedFile.name}</p>
              <div className="flex items-center justify-center gap-4 mt-2 text-sm text-slate-400">
                <span>Size: {formatSize(selectedFile.size)}</span>
                <span className="text-slate-600">|</span>
                <span>Format: EML</span>
                <span className="text-slate-600">|</span>
                <span className="text-green-400">Ready for Analysis</span>
              </div>
            </div>
            {!isAnalyzing && (
              <button
                type="button"
                onClick={(e) => { e.stopPropagation(); inputRef.current?.click(); }}
                className="text-cyan-400 text-sm hover:underline"
              >
                Choose a different file
              </button>
            )}
          </div>
        )}
      </div>

      {/* Error */}
      {error && (
        <div className="mt-4 flex items-center gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Analyze button */}
      <div className="mt-6 text-center">
        <button
          onClick={onAnalyze}
          disabled={!selectedFile || isAnalyzing}
          className={`px-10 py-3.5 rounded-xl font-semibold text-base transition-all ${
            !selectedFile || isAnalyzing
              ? "bg-slate-800 text-slate-600 cursor-not-allowed"
              : "bg-gradient-to-r from-cyan-500 to-blue-600 text-white hover:shadow-lg hover:shadow-cyan-500/30 hover:scale-[1.02]"
          }`}
        >
          {isAnalyzing ? (
            <span className="flex items-center gap-2">
              <Loader2 className="w-5 h-5 animate-spin" />
              Analyzing Email...
            </span>
          ) : (
            "Analyze Email"
          )}
        </button>
      </div>
    </div>
  );
}
