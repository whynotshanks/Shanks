import { useEffect, useRef, useState } from "react";
import { Network, ZoomIn, ZoomOut, Maximize2, Info } from "lucide-react";
import type { AnalysisResult, GraphNode, GraphEdge } from "@/lib/types";

interface GraphViewProps {
  result: AnalysisResult;
}

interface PositionedNode extends GraphNode {
  x: number;
  y: number;
  vx: number;
  vy: number;
}

const NODE_COLORS: Record<string, string> = {
  email: "#0ea5e9",
  sender: "#8b5cf6",
  recipient: "#a78bfa",
  domain: "#06b6d4",
  ip: "#f59e0b",
  url: "#ec4899",
  attachment: "#f97316",
  hash: "#ef4444",
  asn: "#64748b",
  location: "#22c55e",
};

const RISK_GLOW: Record<string, string> = {
  high: "#ef4444",
  medium: "#f59e0b",
  low: "#22c55e",
  none: "#334155",
};

export function InvestigationGraph({ result }: GraphViewProps) {
  const svgRef = useRef<SVGSVGElement>(null);
  const [nodes, setNodes] = useState<PositionedNode[]>([]);
  const [edges, setEdges] = useState<GraphEdge[]>([]);
  const [selectedNode, setSelectedNode] = useState<PositionedNode | null>(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const dragRef = useRef<{ startX: number; startY: number; panX: number; panY: number } | null>(null);
  const animationRef = useRef<number>(0);

  const width = 900;
  const height = 550;

  useEffect(() => {
    const graphNodes = result.graph.nodes;
    const graphEdges = result.graph.edges;

    // Initialize nodes with circular layout
    const centerX = width / 2;
    const centerY = height / 2;
    const initialized = graphNodes.map((node, i) => {
      const angle = (i / graphNodes.length) * Math.PI * 2;
      const radius = Math.min(width, height) * 0.3;
      return {
        ...node,
        x: centerX + Math.cos(angle) * radius + (Math.random() - 0.5) * 50,
        y: centerY + Math.sin(angle) * radius + (Math.random() - 0.5) * 50,
        vx: 0,
        vy: 0,
      };
    });

    setNodes(initialized);
    setEdges(graphEdges);

    // Force simulation
    const nodeMap = new Map(initialized.map((n) => [n.id, n]));
    let frame = 0;
    const maxFrames = 300;

    const simulate = () => {
      if (frame >= maxFrames) return;

      const currentNodes = [...nodeMap.values()];

      // Repulsion between all nodes
      for (let i = 0; i < currentNodes.length; i++) {
        for (let j = i + 1; j < currentNodes.length; j++) {
          const a = currentNodes[i];
          const b = currentNodes[j];
          const dx = b.x - a.x;
          const dy = b.y - a.y;
          const dist = Math.sqrt(dx * dx + dy * dy) + 0.1;
          const force = 3000 / (dist * dist);
          const fx = (dx / dist) * force;
          const fy = (dy / dist) * force;
          a.vx -= fx;
          a.vy -= fy;
          b.vx += fx;
          b.vy += fy;
        }
      }

      // Attraction along edges
      for (const edge of graphEdges) {
        const a = nodeMap.get(edge.source);
        const b = nodeMap.get(edge.target);
        if (!a || !b) continue;
        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const dist = Math.sqrt(dx * dx + dy * dy) + 0.1;
        const force = (dist - 120) * 0.04;
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        a.vx += fx;
        a.vy += fy;
        b.vx -= fx;
        b.vy -= fy;
      }

      // Center gravity
      for (const node of currentNodes) {
        node.vx += (centerX - node.x) * 0.01;
        node.vy += (centerY - node.y) * 0.01;
      }

      // Apply velocity with damping
      for (const node of currentNodes) {
        node.vx *= 0.85;
        node.vy *= 0.85;
        node.x += node.vx;
        node.y += node.vy;
        // Keep in bounds
        node.x = Math.max(40, Math.min(width - 40, node.x));
        node.y = Math.max(30, Math.min(height - 30, node.y));
      }

      frame++;
      setNodes(currentNodes.map((n) => ({ ...n })));
      animationRef.current = requestAnimationFrame(simulate);
    };

    animationRef.current = requestAnimationFrame(simulate);

    return () => {
      if (animationRef.current) cancelAnimationFrame(animationRef.current);
    };
  }, [result]);

  const handleMouseDown = (e: React.MouseEvent) => {
    if (e.target === svgRef.current) {
      setIsDragging(true);
      dragRef.current = { startX: e.clientX, startY: e.clientY, panX: pan.x, panY: pan.y };
    }
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (isDragging && dragRef.current) {
      setPan({
        x: dragRef.current.panX + (e.clientX - dragRef.current.startX),
        y: dragRef.current.panY + (e.clientY - dragRef.current.startY),
      });
    }
  };

  const handleMouseUp = () => {
    setIsDragging(false);
    dragRef.current = null;
  };

  const nodeRadius = (type: string) => {
    if (type === "email") return 22;
    if (type === "sender" || type === "recipient") return 18;
    if (type === "ip" || type === "domain") return 16;
    return 13;
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center">
          <Network className="w-5 h-5 text-cyan-400" />
        </div>
        <div>
          <h2 className="text-xl font-bold text-white">Investigation Graph</h2>
          <p className="text-sm text-slate-500">Visual relationships between email entities and IOCs</p>
        </div>
      </div>

      {/* Controls */}
      <div className="flex items-center gap-2">
        <button
          onClick={() => setZoom((z) => Math.min(z + 0.2, 3))}
          className="p-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-400 hover:text-cyan-400 hover:border-cyan-500/30 transition-colors"
        >
          <ZoomIn className="w-4 h-4" />
        </button>
        <button
          onClick={() => setZoom((z) => Math.max(z - 0.2, 0.3))}
          className="p-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-400 hover:text-cyan-400 hover:border-cyan-500/30 transition-colors"
        >
          <ZoomOut className="w-4 h-4" />
        </button>
        <button
          onClick={() => { setZoom(1); setPan({ x: 0, y: 0 }); }}
          className="p-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-400 hover:text-cyan-400 hover:border-cyan-500/30 transition-colors"
        >
          <Maximize2 className="w-4 h-4" />
        </button>
        <span className="text-sm text-slate-500 ml-2">{result.graph.nodes.length} nodes • {result.graph.edges.length} relationships</span>
      </div>

      {/* Graph */}
      <div className="rounded-xl overflow-hidden border border-slate-700/50 bg-slate-900/60">
        <svg
          ref={svgRef}
          width="100%"
          height={height}
          viewBox={`0 0 ${width} ${height}`}
          style={{ cursor: isDragging ? "grabbing" : "grab" }}
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onMouseLeave={handleMouseUp}
        >
          <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
            {/* Edges */}
            {edges.map((edge, idx) => {
              const source = nodes.find((n) => n.id === edge.source);
              const target = nodes.find((n) => n.id === edge.target);
              if (!source || !target) return null;
              return (
                <g key={idx}>
                  <line
                    x1={source.x}
                    y1={source.y}
                    x2={target.x}
                    y2={target.y}
                    stroke="#334155"
                    strokeWidth={1}
                    strokeOpacity={0.5}
                  />
                  <text
                    x={(source.x + target.x) / 2}
                    y={(source.y + target.y) / 2}
                    fill="#475569"
                    fontSize={8}
                    textAnchor="middle"
                    style={{ pointerEvents: "none" }}
                  >
                    {edge.label.replace(/_/g, " ").toLowerCase()}
                  </text>
                </g>
              );
            })}

            {/* Nodes */}
            {nodes.map((node) => {
              const r = nodeRadius(node.type);
              const color = NODE_COLORS[node.type] || "#64748b";
              const riskGlow = node.risk ? RISK_GLOW[node.risk] : null;
              const isSelected = selectedNode?.id === node.id;

              return (
                <g
                  key={node.id}
                  transform={`translate(${node.x}, ${node.y})`}
                  style={{ cursor: "pointer" }}
                  onClick={() => setSelectedNode(node)}
                >
                  {riskGlow && riskGlow !== "#334155" && (
                    <circle r={r + 6} fill="none" stroke={riskGlow} strokeWidth={2} strokeOpacity={0.4} />
                  )}
                  <circle
                    r={r}
                    fill={color}
                    fillOpacity={0.8}
                    stroke={isSelected ? "#fff" : riskGlow || color}
                    strokeWidth={isSelected ? 3 : 1.5}
                  />
                  <text
                    y={r + 12}
                    textAnchor="middle"
                    fill="#cbd5e1"
                    fontSize={9}
                    style={{ pointerEvents: "none" }}
                  >
                    {node.label.length > 25 ? node.label.slice(0, 23) + "..." : node.label}
                  </text>
                  <text
                    y={4}
                    textAnchor="middle"
                    fill="#fff"
                    fontSize={8}
                    fontWeight="bold"
                    style={{ pointerEvents: "none" }}
                  >
                    {node.type.slice(0, 4).toUpperCase()}
                  </text>
                </g>
              );
            })}
          </g>
        </svg>
      </div>

      {/* Selected node details */}
      {selectedNode && (
        <div className="p-4 rounded-xl bg-slate-800/40 border border-cyan-500/20">
          <h3 className="text-white font-semibold mb-2">Node Details</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
            <div>
              <span className="text-slate-500 text-xs">Label</span>
              <p className="text-slate-200 font-mono break-all">{selectedNode.label}</p>
            </div>
            <div>
              <span className="text-slate-500 text-xs">Type</span>
              <p className="text-cyan-400">{selectedNode.type}</p>
            </div>
            <div>
              <span className="text-slate-500 text-xs">Risk</span>
              <p className={selectedNode.risk === "high" ? "text-red-400" : selectedNode.risk === "medium" ? "text-yellow-400" : "text-slate-400"}>
                {selectedNode.risk || "none"}
              </p>
            </div>
            <div>
              <span className="text-slate-500 text-xs">Connections</span>
              <p className="text-slate-200">
                {edges.filter((e) => e.source === selectedNode.id || e.target === selectedNode.id).length}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Legend */}
      <div className="p-4 rounded-xl bg-slate-800/40 border border-slate-700/50">
        <h3 className="text-white font-semibold mb-3 text-sm">Legend</h3>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-2 text-xs">
          {Object.entries(NODE_COLORS).map(([type, color]) => (
            <div key={type} className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full" style={{ background: color }} />
              <span className="text-slate-400 capitalize">{type}</span>
            </div>
          ))}
        </div>
        <div className="mt-3 pt-3 border-t border-slate-700/30 flex items-center gap-4">
          <div className="flex items-center gap-2">
            <div className="w-4 h-4 rounded-full border-2 border-red-500" />
            <span className="text-slate-400 text-xs">High Risk</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-4 h-4 rounded-full border-2 border-yellow-500" />
            <span className="text-slate-400 text-xs">Medium Risk</span>
          </div>
        </div>
      </div>

      {/* Info */}
      <div className="p-4 rounded-lg bg-slate-800/40 border-l-4 border-cyan-500/40">
        <div className="flex items-center gap-2 mb-1">
          <Info className="w-4 h-4 text-cyan-400" />
          <h4 className="text-cyan-400 text-sm font-semibold">How to Read This Graph</h4>
        </div>
        <p className="text-xs text-slate-400 leading-relaxed">
          Nodes represent entities extracted from the email (sender, IPs, domains, URLs, attachments, locations).
          Edges show relationships (SENT_BY, ROUTED_THROUGH, RESOLVES_TO, CONTAINS, etc.).
          Click any node to see details. Use zoom controls or scroll to zoom. Drag the background to pan.
        </p>
      </div>
    </div>
  );
}
