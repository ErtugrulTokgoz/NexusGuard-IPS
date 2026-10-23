/**
 * @file src/app/logs/page.tsx
 * @description NexusGuard IPS — Güvenlik Logları Sayfası
 *
 * Özellikler:
 * - MitM/ARP saldırı logları (threat_logs tablosu) — filtreli
 * - Taranan URL sonuçları (url_scans tablosu)
 * - Sekme geçişi ile iki tablo arasında gezinme
 * - Supabase Realtime ile canlı güncelleme
 */

"use client";

import { useState, useEffect, useCallback } from "react";
import { createSupabaseClient, ThreatLog, UrlScan } from "@/lib/supabase";
import {
  ShieldExclamationIcon,
  LinkIcon,
  FunnelIcon,
} from "@heroicons/react/24/outline";

// ── Rozet Bileşenleri ────────────────────────────────────────────────────

function ThreatTypeBadge({ type }: { type: string }) {
  const colors: Record<string, string> = {
    ARP_SPOOFING: "bg-red-500/10 text-red-400 border-red-500/30",
    MITM: "bg-orange-500/10 text-orange-400 border-orange-500/30",
    PORT_SCAN: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
    DOS: "bg-purple-500/10 text-purple-400 border-purple-500/30",
  };

  return (
    <span
      className={`px-2 py-1 rounded text-xs font-mono font-medium border ${
        colors[type] ?? "bg-gray-700 text-gray-300 border-gray-600"
      }`}
    >
      {type}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    ACTIVE: "bg-red-500/10 text-red-400",
    INVESTIGATING: "bg-yellow-500/10 text-yellow-400",
    MITIGATED: "bg-green-500/10 text-green-400",
  };

  return (
    <span className={`px-2 py-1 rounded-full text-xs font-medium ${colors[status] ?? "text-gray-400"}`}>
      {status}
    </span>
  );
}

function VerdictBadge({ verdict, score }: { verdict: string; score: number }) {
  const colors: Record<string, string> = {
    SAFE: "bg-green-500/10 text-green-400 border-green-500/30",
    SUSPICIOUS: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
    MALICIOUS: "bg-orange-500/10 text-orange-400 border-orange-500/30",
    PHISHING: "bg-red-500/10 text-red-400 border-red-500/30",
    ERROR: "bg-gray-700 text-gray-400 border-gray-600",
  };

  return (
    <span
      className={`px-2 py-1 rounded text-xs font-medium border ${
        colors[verdict] ?? "bg-gray-700 text-gray-300 border-gray-600"
      }`}
    >
      {verdict} · {score}/100
    </span>
  );
}

// ── Ana Bileşen ────────────────────────────────────────────────────────

type TabType = "threats" | "scans";

export default function LogsPage() {
  const [activeTab, setActiveTab] = useState<TabType>("threats");
  const [threats, setThreats] = useState<ThreatLog[]>([]);
  const [urlScans, setUrlScans] = useState<UrlScan[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterType, setFilterType] = useState("ALL");

  // ── Veri yükleme ─────────────────────────────────────────────────────
  const fetchLogs = useCallback(async () => {
    const supabase = createSupabaseClient();
    setLoading(true);

    const [threatRes, scanRes] = await Promise.all([
      supabase
        .from("threat_logs")
        .select("*")
        .order("created_at", { ascending: false })
        .limit(100),
      supabase
        .from("url_scans")
        .select("*")
        .order("created_at", { ascending: false })
        .limit(100),
    ]);

    if (threatRes.data) setThreats(threatRes.data);
    if (scanRes.data) setUrlScans(scanRes.data);
    setLoading(false);
  }, []);

  // ── Realtime aboneliği ────────────────────────────────────────────────
  useEffect(() => {
    fetchLogs();
    const supabase = createSupabaseClient();

    const threatSub = supabase
      .channel("logs-threats")
      .on(
        "postgres_changes",
        { event: "INSERT", schema: "public", table: "threat_logs" },
        (payload) => setThreats((prev) => [payload.new as ThreatLog, ...prev])
      )
      .subscribe();

    const scanSub = supabase
      .channel("logs-scans")
      .on(
        "postgres_changes",
        { event: "INSERT", schema: "public", table: "url_scans" },
        (payload) => setUrlScans((prev) => [payload.new as UrlScan, ...prev])
      )
      .subscribe();

    return () => {
      supabase.removeChannel(threatSub);
      supabase.removeChannel(scanSub);
    };
  }, [fetchLogs]);

  // ── Filtreleme ────────────────────────────────────────────────────────
  const filteredThreats =
    filterType === "ALL"
      ? threats
      : threats.filter((t) => t.threat_type === filterType);

  const THREAT_TYPES = ["ALL", "ARP_SPOOFING", "MITM", "PORT_SCAN", "DOS"];

  const dateFormat = (iso: string) =>
    new Date(iso).toLocaleString("tr-TR", {
      day: "2-digit",
      month: "2-digit",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">

      {/* ── Başlık ── */}
      <div>
        <h1 className="text-2xl font-bold text-white">Güvenlik Logları</h1>
        <p className="text-sm text-gray-500 mt-1">
          Tüm tehdit ve URL tarama kayıtları kronolojik sırada · Canlı güncelleme
        </p>
      </div>

      {/* ── Sekmeler ── */}
      <div className="flex gap-2 border-b border-gray-800">
        {(
          [
            { id: "threats", label: "Tehdit Logları", icon: ShieldExclamationIcon, count: threats.length },
            { id: "scans",   label: "URL Taramaları", icon: LinkIcon,              count: urlScans.length },
          ] as const
        ).map(({ id, label, icon: Icon, count }) => (
          <button
            key={id}
            onClick={() => setActiveTab(id)}
            className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
              activeTab === id
                ? "border-cyan-500 text-cyan-400"
                : "border-transparent text-gray-500 hover:text-gray-300"
            }`}
          >
            <Icon className="w-4 h-4" />
            {label}
            <span className="ml-1 px-1.5 py-0.5 rounded-full text-xs bg-gray-800 text-gray-400">
              {count}
            </span>
          </button>
        ))}
      </div>

      {/* ── Tehdit Logları Tablosu ── */}
      {activeTab === "threats" && (
        <div className="space-y-4">
          {/* Filtre butonları */}
          <div className="flex items-center gap-2 flex-wrap">
            <FunnelIcon className="w-4 h-4 text-gray-500 flex-shrink-0" />
            {THREAT_TYPES.map((type) => (
              <button
                key={type}
                onClick={() => setFilterType(type)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                  filterType === type
                    ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/20"
                    : "text-gray-500 hover:text-gray-300 hover:bg-gray-800"
                }`}
              >
                {type}
              </button>
            ))}
          </div>

          <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-xs text-gray-500 uppercase tracking-wider border-b border-gray-800 bg-gray-900/50">
                    <th className="px-5 py-3 text-left">Tehdit Türü</th>
                    <th className="px-5 py-3 text-left">Saldırgan</th>
                    <th className="px-5 py-3 text-left">Hedef</th>
                    <th className="px-5 py-3 text-left">Durum</th>
                    <th className="px-5 py-3 text-left">Kill-Switch</th>
                    <th className="px-5 py-3 text-left">Zaman</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800/50">
                  {loading ? (
                    <tr>
                      <td colSpan={6} className="px-5 py-12 text-center text-gray-600">
                        Loglar yükleniyor...
                      </td>
                    </tr>
                  ) : filteredThreats.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="px-5 py-12 text-center text-gray-600">
                        Bu filtre için kayıt bulunamadı
                      </td>
                    </tr>
                  ) : (
                    filteredThreats.map((t) => (
                      <tr key={t.id} className="hover:bg-gray-800/20 transition-colors">
                        <td className="px-5 py-3">
                          <ThreatTypeBadge type={t.threat_type} />
                        </td>
                        <td className="px-5 py-3">
                          <div className="font-mono text-xs text-gray-300">
                            {t.attacker_ip ?? "—"}
                          </div>
                          <div className="font-mono text-xs text-gray-600">
                            {t.attacker_mac ?? ""}
                          </div>
                        </td>
                        <td className="px-5 py-3">
                          <div className="font-mono text-xs text-gray-300">
                            {t.victim_ip ?? "—"}
                          </div>
                          <div className="font-mono text-xs text-gray-600">
                            {t.victim_mac ?? ""}
                          </div>
                        </td>
                        <td className="px-5 py-3">
                          <StatusBadge status={t.status} />
                        </td>
                        <td className="px-5 py-3">
                          {t.kill_switch_triggered ? (
                            <span className="text-xs font-medium text-red-400">
                              ● Tetiklendi
                            </span>
                          ) : (
                            <span className="text-xs text-gray-600">○ Hayır</span>
                          )}
                        </td>
                        <td className="px-5 py-3 text-xs text-gray-500">
                          {dateFormat(t.created_at)}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ── URL Tarama Logları Tablosu ── */}
      {activeTab === "scans" && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-xs text-gray-500 uppercase tracking-wider border-b border-gray-800 bg-gray-900/50">
                  <th className="px-5 py-3 text-left">URL</th>
                  <th className="px-5 py-3 text-left">Karar</th>
                  <th className="px-5 py-3 text-left">Tetikleyen</th>
                  <th className="px-5 py-3 text-left">Zaman</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/50">
                {loading ? (
                  <tr>
                    <td colSpan={4} className="px-5 py-12 text-center text-gray-600">
                      Loglar yükleniyor...
                    </td>
                  </tr>
                ) : urlScans.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="px-5 py-12 text-center text-gray-600">
                      Henüz URL taraması yapılmamış
                    </td>
                  </tr>
                ) : (
                  urlScans.map((s) => (
                    <tr key={s.id} className="hover:bg-gray-800/20 transition-colors">
                      <td className="px-5 py-3 max-w-xs">
                        <p className="text-xs text-gray-300 truncate font-mono">
                          {s.url}
                        </p>
                      </td>
                      <td className="px-5 py-3">
                        <VerdictBadge verdict={s.verdict} score={s.risk_score} />
                      </td>
                      <td className="px-5 py-3 text-xs text-gray-500">
                        {s.triggered_by}
                      </td>
                      <td className="px-5 py-3 text-xs text-gray-500">
                        {dateFormat(s.created_at)}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
