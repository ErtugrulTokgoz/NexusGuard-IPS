/**
 * @file src/app/topology/page.tsx
 * @description NexusGuard IPS — Canlı Ağ Topolojisi Sayfası
 *
 * react-force-graph-2d kütüphanesi ile ağdaki cihazları hareketli
 * node'lar halinde görselleştirir.
 *
 * Renk kodlaması:
 *  Cyan  → Gateway / Router (.1 ile biten IP)
 *  Yeşil → Normal cihaz
 *  Sarı  → Şüpheli cihaz
 *  Kırmızı → Engellenmiş cihaz
 *
 * Supabase Realtime ile cihaz listesi otomatik güncellenir.
 */

"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import { createSupabaseClient, NetworkDevice } from "@/lib/supabase";
import {
  WifiIcon,
  ShieldExclamationIcon,
  NoSymbolIcon,
  ArrowPathIcon,
} from "@heroicons/react/24/outline";

// ── Graph Veri Tipleri ──────────────────────────────────────────────────

interface GraphNode {
  id: string;
  label: string;
  ip: string;
  mac: string;
  isSuspicious: boolean;
  isBlocked: boolean;
  isGateway: boolean;
  color: string;
  val: number;
}

interface GraphLink {
  source: string;
  target: string;
}

interface GraphData {
  nodes: GraphNode[];
  links: GraphLink[];
}

// ── Cihaz Özet Kartı ────────────────────────────────────────────────────

function DeviceCard({ device }: { device: NetworkDevice }) {
  const borderColor = device.is_blocked
    ? "border-red-500/40 bg-red-500/5"
    : device.is_suspicious
    ? "border-yellow-500/40 bg-yellow-500/5"
    : "border-gray-700 bg-gray-800/50";

  return (
    <div className={`rounded-lg border p-3 transition-colors ${borderColor}`}>
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="text-xs font-mono text-gray-300 truncate">
            {device.ip_address}
          </p>
          <p className="text-xs text-gray-600 font-mono truncate mt-0.5">
            {device.mac_address}
          </p>
          {device.hostname && (
            <p className="text-xs text-gray-500 truncate mt-0.5">
              {device.hostname}
            </p>
          )}
        </div>
        <div className="flex-shrink-0">
          {device.is_blocked ? (
            <NoSymbolIcon className="w-4 h-4 text-red-400" />
          ) : device.is_suspicious ? (
            <ShieldExclamationIcon className="w-4 h-4 text-yellow-400" />
          ) : (
            <WifiIcon className="w-4 h-4 text-green-400" />
          )}
        </div>
      </div>
      {device.vendor && (
        <p className="text-xs text-gray-600 mt-1 truncate">{device.vendor}</p>
      )}
    </div>
  );
}

// ── Ana Sayfa Bileşeni ─────────────────────────────────────────────────

export default function TopologyPage() {
  const [devices, setDevices] = useState<NetworkDevice[]>([]);
  const [loading, setLoading] = useState(true);
  const [graphData, setGraphData] = useState<GraphData>({ nodes: [], links: [] });
  const graphContainerRef = useRef<HTMLDivElement>(null);
  const [containerWidth, setContainerWidth] = useState(800);

  // ForceGraph — SSR'siz dynamic import
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [ForceGraph, setForceGraph] = useState<React.ComponentType<any> | null>(null);

  useEffect(() => {
    import("react-force-graph-2d")
      .then((mod) => setForceGraph(() => mod.default))
      .catch(console.error);
  }, []);

  // Container genişliğini ölç
  useEffect(() => {
    if (!graphContainerRef.current) return;
    const observer = new ResizeObserver((entries) => {
      setContainerWidth(entries[0].contentRect.width);
    });
    observer.observe(graphContainerRef.current);
    return () => observer.disconnect();
  }, []);

  // ── Graph verisini oluştur ──────────────────────────────────────────
  const buildGraphData = useCallback((deviceList: NetworkDevice[]): GraphData => {
    const gatewayDevice = deviceList.find((d) => d.ip_address.endsWith(".1"));

    const nodes: GraphNode[] = deviceList.map((d) => ({
      id: d.id,
      label: d.hostname ?? d.ip_address,
      ip: d.ip_address,
      mac: d.mac_address,
      isSuspicious: d.is_suspicious,
      isBlocked: d.is_blocked,
      isGateway: d.id === gatewayDevice?.id,
      color: d.is_blocked
        ? "#ef4444"   // Kırmızı — engellenmiş
        : d.is_suspicious
        ? "#eab308"   // Sarı — şüpheli
        : d.id === gatewayDevice?.id
        ? "#22d3ee"   // Cyan — gateway
        : "#4ade80",  // Yeşil — normal
      val: d.id === gatewayDevice?.id ? 15 : d.is_suspicious ? 10 : 7,
    }));

    // Her cihazı gateway'e bağla
    const links: GraphLink[] = gatewayDevice
      ? nodes
          .filter((n) => n.id !== gatewayDevice.id)
          .map((n) => ({ source: gatewayDevice.id, target: n.id }))
      : [];

    return { nodes, links };
  }, []);

  // ── Cihaz verisi çek ───────────────────────────────────────────────
  const fetchDevices = useCallback(async () => {
    const res = await fetch("/api/devices");
    if (res.ok) {
      const data = await res.json();
      const list: NetworkDevice[] = data.devices ?? [];
      setDevices(list);
      setGraphData(buildGraphData(list));
    }
    setLoading(false);
  }, [buildGraphData]);

  // ── Supabase Realtime ──────────────────────────────────────────────
  useEffect(() => {
    fetchDevices();
    const supabase = createSupabaseClient();

    const sub = supabase
      .channel("topology-devices")
      .on(
        "postgres_changes",
        { event: "*", schema: "public", table: "network_devices" },
        () => fetchDevices()
      )
      .subscribe();

    return () => { supabase.removeChannel(sub); };
  }, [fetchDevices]);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">

      {/* ── Başlık ── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Ağ Topolojisi</h1>
          <p className="text-sm text-gray-500 mt-1">
            {devices.length} cihaz tespit edildi · Canlı güncelleme aktif
          </p>
        </div>
        <button
          onClick={fetchDevices}
          className="flex items-center gap-2 px-4 py-2 text-sm text-gray-400 hover:text-white bg-gray-800 hover:bg-gray-700 rounded-lg border border-gray-700 transition-colors"
        >
          <ArrowPathIcon className="w-4 h-4" />
          Yenile
        </button>
      </div>

      {/* ── Renk Kodlaması ── */}
      <div className="flex flex-wrap gap-4 text-xs text-gray-500">
        {[
          { color: "bg-cyan-400", label: "Gateway / Router" },
          { color: "bg-green-400", label: "Normal Cihaz" },
          { color: "bg-yellow-400", label: "Şüpheli Cihaz" },
          { color: "bg-red-400", label: "Engellenmiş Cihaz" },
        ].map(({ color, label }) => (
          <div key={label} className="flex items-center gap-1.5">
            <span className={`w-3 h-3 rounded-full ${color}`} />
            {label}
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* ── Graf Görünümü ── */}
        <div
          ref={graphContainerRef}
          className="lg:col-span-2 bg-gray-900 border border-gray-800 rounded-xl overflow-hidden"
          style={{ height: "500px" }}
        >
          {loading ? (
            <div className="flex items-center justify-center h-full text-gray-600">
              <ArrowPathIcon className="w-6 h-6 animate-spin mr-2" />
              Yükleniyor...
            </div>
          ) : !ForceGraph ? (
            <div className="flex items-center justify-center h-full text-gray-600 text-sm">
              Graf motoru başlatılıyor...
            </div>
          ) : devices.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-gray-600">
              <WifiIcon className="w-12 h-12 mb-3 opacity-30" />
              <p className="text-sm">Henüz cihaz tespit edilmedi</p>
              <p className="text-xs mt-1 text-gray-700">
                Python IPS motoru çalışmıyor olabilir
              </p>
            </div>
          ) : (
            <ForceGraph
              graphData={graphData}
              nodeLabel={(node: GraphNode) =>
                `${node.label}\n${node.ip}\n${node.mac}`
              }
              nodeColor={(node: GraphNode) => node.color}
              nodeVal={(node: GraphNode) => node.val}
              linkColor={() => "#374151"}
              backgroundColor="#030712"
              width={containerWidth}
              height={500}
            />
          )}
        </div>

        {/* ── Cihaz Listesi ── */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-gray-800">
            <h2 className="text-sm font-semibold text-white">Cihaz Listesi</h2>
          </div>
          <div className="p-3 space-y-2 overflow-y-auto" style={{ maxHeight: "456px" }}>
            {loading ? (
              <p className="text-center text-gray-600 text-sm py-8">Yükleniyor...</p>
            ) : devices.length === 0 ? (
              <p className="text-center text-gray-600 text-sm py-8">Cihaz bulunamadı</p>
            ) : (
              devices.map((d) => <DeviceCard key={d.id} device={d} />)
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
