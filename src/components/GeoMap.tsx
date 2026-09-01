import { useEffect, useRef } from "react";
import { MapPin, AlertTriangle, Info } from "lucide-react";
import type { AnalysisResult, GeoLocation } from "@/lib/types";
import type { Map as LeafletMap, LayerGroup } from "leaflet";

declare global {
  interface Window {
    L: typeof import("leaflet");
  }
}

interface GeoMapProps {
  result: AnalysisResult;
}

export function GeoMap({ result }: GeoMapProps) {
  const mapRef = useRef<HTMLDivElement>(null);
  const mapInstanceRef = useRef<LeafletMap | null>(null);
  const layerRef = useRef<LayerGroup | null>(null);

  const validGeos = result.geolocation.filter((g) => g.success && g.latitude && g.longitude);

  useEffect(() => {
    if (!mapRef.current || !window.L) return;
    const L = window.L;

    if (!mapInstanceRef.current) {
      const map = L.map(mapRef.current, {
        center: [20, 0],
        zoom: 2,
        worldCopyJump: true,
        zoomControl: true,
      });

      L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
        attribution: '&copy; OpenStreetMap contributors',
        maxZoom: 18,
      }).addTo(map);

      mapInstanceRef.current = map;
      layerRef.current = L.layerGroup().addTo(map);
    }

    const map = mapInstanceRef.current;
    const layer = layerRef.current;
    if (!map || !layer) return;

    layer.clearLayers();

    const hopIPs = result.headers
      .map((h) => h.sourceIp)
      .filter((ip) => ip && result.indicators.ips.find((i) => i.address === ip)?.classification === "public");

    const geoByIP = new Map<string, GeoLocation>();
    validGeos.forEach((g) => geoByIP.set(g.ip, g));

    const routePoints: { geo: GeoLocation; hopIndex: number }[] = [];
    hopIPs.forEach((ip, idx) => {
      const geo = geoByIP.get(ip);
      if (geo) routePoints.push({ geo, hopIndex: idx });
    });

    validGeos.forEach((geo) => {
      if (!routePoints.find((rp) => rp.geo.ip === geo.ip)) {
        routePoints.push({ geo, hopIndex: -1 });
      }
    });

    if (routePoints.length === 0) return;

    const markers: [number, number][] = [];
    const colors = ["#22c55e", "#eab308", "#f97316", "#ef4444"];

    routePoints.forEach((rp) => {
      const { geo } = rp;
      const ipIndicator = result.indicators.ips.find((i) => i.address === geo.ip);
      const threatScore = ipIndicator?.threat?.score || 0;
      const reputation = ipIndicator?.threat?.reputation || "unknown";

      const markerColor = reputation === "malicious" ? colors[3] :
        reputation === "suspicious" ? colors[2] :
        threatScore > 30 ? colors[1] : colors[0];

      const marker = L.circleMarker([geo.latitude, geo.longitude], {
        radius: 10,
        fillColor: markerColor,
        color: "#fff",
        weight: 2,
        opacity: 1,
        fillOpacity: 0.85,
      });

      const hopLabel = rp.hopIndex >= 0 ? `Hop ${rp.hopIndex + 1}` : "Additional IP";
      const popupContent = `
        <div style="font-family: 'Segoe UI', sans-serif; min-width: 220px; padding: 4px;">
          <div style="font-size: 13px; font-weight: 700; color: #0ea5e9; margin-bottom: 8px;">${hopLabel} &mdash; ${geo.ip}</div>
          <table style="font-size: 12px; width: 100%; border-collapse: collapse;">
            <tr><td style="color: #64748b; padding: 2px 8px 2px 0;">Location</td><td style="font-weight: 600;">${geo.city}, ${geo.region}, ${geo.country}</td></tr>
            <tr><td style="color: #64748b; padding: 2px 8px 2px 0;">ISP</td><td>${geo.isp || "N/A"}</td></tr>
            <tr><td style="color: #64748b; padding: 2px 8px 2px 0;">ASN</td><td>${geo.asn || "N/A"}</td></tr>
            <tr><td style="color: #64748b; padding: 2px 8px 2px 0;">Org</td><td>${geo.org || "N/A"}</td></tr>
            <tr><td style="color: #64748b; padding: 2px 8px 2px 0;">Threat</td><td style="color: ${reputation === "malicious" ? "#ef4444" : reputation === "suspicious" ? "#eab308" : "#22c55e"}; font-weight: 600;">${reputation.toUpperCase()} (${threatScore})</td></tr>
            <tr><td style="color: #64748b; padding: 2px 8px 2px 0;">Coords</td><td style="font-family: monospace; font-size: 11px;">${geo.latitude.toFixed(3)}, ${geo.longitude.toFixed(3)}</td></tr>
          </table>
        </div>
      `;
      marker.bindPopup(popupContent);
      layer.addLayer(marker);
      markers.push([geo.latitude, geo.longitude]);

      if (rp.hopIndex >= 0) {
        const label = L.marker([geo.latitude, geo.longitude], {
          icon: L.divIcon({
            className: "hop-label",
            html: `<div style="background: ${markerColor}; color: white; border-radius: 50%; width: 22px; height: 22px; display: flex; align-items: center; justify-content: center; font-size: 11px; font-weight: bold; border: 2px solid white; box-shadow: 0 2px 4px rgba(0,0,0,0.5);">${rp.hopIndex + 1}</div>`,
            iconSize: [22, 22],
            iconAnchor: [11, 11],
          }),
        });
        layer.addLayer(label);
      }
    });

    const hopPoints = routePoints.filter((rp) => rp.hopIndex >= 0).sort((a, b) => a.hopIndex - b.hopIndex);
    if (hopPoints.length > 1) {
      const latlngs: [number, number][] = hopPoints.map((rp) => [rp.geo.latitude, rp.geo.longitude]);
      const routeLine = L.polyline(latlngs, {
        color: "#0ea5e9",
        weight: 2,
        opacity: 0.5,
        dashArray: "8, 6",
      });
      layer.addLayer(routeLine);
    }

    if (markers.length > 0) {
      const bounds = L.latLngBounds(markers);
      map.fitBounds(bounds, { padding: [50, 50], maxZoom: 8 });
    }

    setTimeout(() => map.invalidateSize(), 100);
  }, [result]);

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center">
          <MapPin className="w-5 h-5 text-cyan-400" />
        </div>
        <div>
          <h2 className="text-xl font-bold text-white">Geo-Forensic Email Route Mapping</h2>
          <p className="text-sm text-slate-500">Geographic visualization of email infrastructure</p>
        </div>
      </div>

      <div className="rounded-xl overflow-hidden border border-slate-700/50">
        <div ref={mapRef} style={{ height: "500px", width: "100%", background: "#1e293b" }} />
      </div>

      <div className="flex items-center gap-4 flex-wrap text-sm">
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded-full bg-green-500 border-2 border-white" />
          <span className="text-slate-400">Clean</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded-full bg-yellow-500 border-2 border-white" />
          <span className="text-slate-400">Suspicious</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded-full bg-orange-500 border-2 border-white" />
          <span className="text-slate-400">Elevated</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded-full bg-red-500 border-2 border-white" />
          <span className="text-slate-400">Malicious</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-6 h-0.5 bg-cyan-400 border-t border-dashed" />
          <span className="text-slate-400">Mail Route</span>
        </div>
      </div>

      <div className="p-5 rounded-xl bg-slate-800/40 border border-slate-700/50">
        <h3 className="text-white font-semibold mb-3">IP Geolocation Details</h3>
        {validGeos.length === 0 ? (
          <div className="flex items-center gap-2 text-sm text-slate-500">
            <AlertTriangle className="w-4 h-4 text-yellow-400" />
            No publicly routable IP addresses were available for geographic mapping.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-slate-500 text-xs uppercase tracking-wider border-b border-slate-700">
                  <th className="pb-2 pr-4">IP Address</th>
                  <th className="pb-2 pr-4">Location</th>
                  <th className="pb-2 pr-4">ISP</th>
                  <th className="pb-2 pr-4">ASN</th>
                  <th className="pb-2 pr-4">Threat</th>
                </tr>
              </thead>
              <tbody>
                {validGeos.map((geo) => {
                  const ipInd = result.indicators.ips.find((i) => i.address === geo.ip);
                  const rep = ipInd?.threat?.reputation || "unknown";
                  return (
                    <tr key={geo.ip} className="border-b border-slate-800/50">
                      <td className="py-2.5 pr-4 font-mono text-cyan-400">{geo.ip}</td>
                      <td className="py-2.5 pr-4 text-slate-300">{geo.city}, {geo.region}, {geo.country}</td>
                      <td className="py-2.5 pr-4 text-slate-400">{geo.isp || "N/A"}</td>
                      <td className="py-2.5 pr-4 text-slate-400 font-mono">{geo.asn || "N/A"}</td>
                      <td className="py-2.5 pr-4">
                        <span className={`font-semibold ${
                          rep === "malicious" ? "text-red-400" :
                          rep === "suspicious" ? "text-yellow-400" : "text-green-400"
                        }`}>{rep.toUpperCase()}</span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="p-4 rounded-lg bg-orange-500/5 border-l-4 border-orange-500/40">
        <div className="flex items-center gap-2 mb-1">
          <Info className="w-4 h-4 text-orange-400" />
          <h4 className="text-orange-400 text-sm font-semibold">Geolocation Disclaimer</h4>
        </div>
        <p className="text-xs text-slate-400 leading-relaxed">
          IP geolocation is an approximate geographic association and does not identify a person or exact physical location.
          The most recent public mail server is not automatically the original attacker IP. Email headers can be spoofed or manipulated.
        </p>
      </div>
    </div>
  );
}
