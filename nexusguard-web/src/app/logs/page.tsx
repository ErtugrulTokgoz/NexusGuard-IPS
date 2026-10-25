/**
 * @file src/app/logs/page.tsx
 * @description NexusGuard IPS — Güvenlik Logları Sayfası
 */

"use client";

import { useState, useEffect, useCallback } from "react";
import { createSupabaseClient, UrlScan } from "@/lib/supabase";
import {
  ShieldExclamationIcon,
  LinkIcon,
  FunnelIcon,
  MagnifyingGlassIcon,
  CalendarDaysIcon,
  ArrowPathIcon,
  XMarkIcon,
} from "@heroicons/react/24/outline";

// Yeni Python motorumuzun gönderdiği veri tipi
interface NetworkAlert {
  id: string;
  created_at: string;
  target_ip: string;
  original_mac: string;
  attacker_mac: string;
}

// ── Rozet Bileşenleri ────────────────────────────────────────────────────
function ThreatTypeBadge() {
  return (
    <span className="px-2 py-1 rounded text-xs font-mono font-medium border bg-red-500/10 text-red-400 border-red-500/30">
      ARP_SPOOFING
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
type TabType = "alerts" | "scans";

export default function LogsPage() {
  const [activeTab, setActiveTab] = useState<TabType>("alerts");
  const [alerts, setAlerts] = useState<NetworkAlert[]>([]);
  const [urlScans, setUrlScans] = useState<UrlScan[]>([]);
  const [loading, setLoading] = useState(true);

  // Filtreleme Durumları
  const [ipFilter, setIpFilter] = useState("");
  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");

  // ── Supabase Verilerini Filtre ile Çek ────────────────────────────────
  const fetchLogs = useCallback(
    async (overrideFilters?: { ip?: string; start?: string; end?: string }) => {
      const supabase = createSupabaseClient();
      setLoading(true);

      const targetIp = overrideFilters?.ip !== undefined ? overrideFilters.ip : ipFilter;
      const targetStart = overrideFilters?.start !== undefined ? overrideFilters.start : startDate;
      const targetEnd = overrideFilters?.end !== undefined ? overrideFilters.end : endDate;

      try {
        // 1. Network Alerts (IDS) Sorgusu
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        let alertQuery = (supabase as any)
          .from("network_alerts")
          .select("*")
          .order("created_at", { ascending: false })
          .limit(100);

        if (targetIp.trim()) {
          alertQuery = alertQuery.ilike("target_ip", `%${targetIp.trim()}%`);
        }
        if (targetStart) {
          const startIso = new Date(targetStart).toISOString();
          alertQuery = alertQuery.gte("created_at", startIso);
        }
        if (targetEnd) {
          const endObj = new Date(targetEnd);
          endObj.setHours(23, 59, 59, 999);
          alertQuery = alertQuery.lte("created_at", endObj.toISOString());
        }

        // 2. URL Scans Sorgusu
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        let scanQuery = (supabase as any)
          .from("url_scans")
          .select("*")
          .order("created_at", { ascending: false })
          .limit(100);

        if (targetStart) {
          const startIso = new Date(targetStart).toISOString();
          scanQuery = scanQuery.gte("created_at", startIso);
        }
        if (targetEnd) {
          const endObj = new Date(targetEnd);
          endObj.setHours(23, 59, 59, 999);
          scanQuery = scanQuery.lte("created_at", endObj.toISOString());
        }

        const [alertRes, scanRes] = await Promise.all([alertQuery, scanQuery]);

        if (alertRes.data) setAlerts(alertRes.data);
        if (scanRes.data) setUrlScans(scanRes.data);
      } catch (err) {
        console.error("[logs] Veri çekme hatası:", err);
      } finally {
        setLoading(false);
      }
    },
    [ipFilter, startDate, endDate]
  );

  // ── İlk Yükleme ve Realtime Aboneliği ──────────────────────────────────
  useEffect(() => {
    fetchLogs();
    const supabase = createSupabaseClient();

    const alertSub = supabase
      .channel("logs-alerts")
      .on(
        "postgres_changes",
        { event: "INSERT", schema: "public", table: "network_alerts" },
        (payload) => setAlerts((prev) => [payload.new as NetworkAlert, ...prev])
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
      supabase.removeChannel(alertSub);
      supabase.removeChannel(scanSub);
    };
  }, [fetchLogs]);

  // ── Filtreleri Sıfırla ────────────────────────────────────────────────
  const handleResetFilters = () => {
    setIpFilter("");
    setStartDate("");
    setEndDate("");
    fetchLogs({ ip: "", start: "", end: "" });
  };

  const dateFormat = (iso: string) =>
    new Date(iso).toLocaleString("tr-TR", {
      day: "2-digit",
      month: "2-digit",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });

  const isFilterActive = Boolean(ipFilter.trim()) || Boolean(startDate) || Boolean(endDate);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      {/* ── Başlık ── */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Güvenlik Logları</h1>
          <p className="text-sm text-gray-500 mt-1">
            Tüm tehdit ve URL tarama kayıtları kronolojik sırada · Canlı izleme
          </p>
        </div>
        <button
          onClick={() => fetchLogs()}
          disabled={loading}
          className="self-start sm:self-auto flex items-center gap-2 px-4 py-2 text-sm text-gray-300 hover:text-white bg-gray-800 hover:bg-gray-700 rounded-lg border border-gray-700 transition-colors disabled:opacity-50 cursor-pointer"
        >
          <ArrowPathIcon className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          Yenile
        </button>
      </div>

      {/* ── Sekmeler ── */}
      <div className="flex gap-2 border-b border-gray-800">
        {(
          [
            { id: "alerts", label: "Ağ Alarmları (IDS)", icon: ShieldExclamationIcon, count: alerts.length },
            { id: "scans", label: "URL Taramaları", icon: LinkIcon, count: urlScans.length },
          ] as const
        ).map(({ id, label, icon: Icon, count }) => (
          <button
            key={id}
            onClick={() => setActiveTab(id)}
            className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors cursor-pointer ${
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

      {/* ── Gelişmiş Filtreleme Bölümü ── */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-sm font-semibold text-gray-300">
            <FunnelIcon className="w-4 h-4 text-cyan-400" />
            <span>Supabase Filtreleme & Arama</span>
          </div>
          {isFilterActive && (
            <button
              onClick={handleResetFilters}
              className="flex items-center gap-1 text-xs text-red-400 hover:text-red-300 transition-colors cursor-pointer"
            >
              <XMarkIcon className="w-3.5 h-3.5" />
              Filtreleri Temizle
            </button>
          )}
        </div>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            fetchLogs();
          }}
          className="grid grid-cols-1 md:grid-cols-10 gap-3"
        >
          {/* IP Adresi Arama */}
          <div className="md:col-span-4 relative">
            <label className="block text-xs font-medium text-gray-400 mb-1">Hedef IP Adresi</label>
            <div className="relative">
              <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
              <input
                type="text"
                placeholder="Örn: 192.168.1.99"
                value={ipFilter}
                onChange={(e) => setIpFilter(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg pl-9 pr-3 py-2 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          {/* Başlangıç Tarihi */}
          <div className="md:col-span-2">
            <label className="block text-xs font-medium text-gray-400 mb-1">Başlangıç</label>
            <div className="relative">
              <CalendarDaysIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500 pointer-events-none" />
              <input
                type="date"
                value={startDate}
                onChange={(e) => setStartDate(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg pl-9 pr-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 [color-scheme:dark]"
              />
            </div>
          </div>

          {/* Bitiş Tarihi */}
          <div className="md:col-span-2">
            <label className="block text-xs font-medium text-gray-400 mb-1">Bitiş</label>
            <div className="relative">
              <CalendarDaysIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500 pointer-events-none" />
              <input
                type="date"
                value={endDate}
                onChange={(e) => setEndDate(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg pl-9 pr-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 [color-scheme:dark]"
              />
            </div>
          </div>

          {/* Filtrele Butonu */}
          <div className="md:col-span-2 flex items-end">
            <button
              type="submit"
              disabled={loading}
              className="w-full py-2 bg-cyan-500 hover:bg-cyan-400 text-gray-950 font-semibold rounded-lg text-xs transition-colors flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-50"
            >
              {loading ? (
                <ArrowPathIcon className="w-4 h-4 animate-spin" />
              ) : (
                <MagnifyingGlassIcon className="w-4 h-4" />
              )}
              Sorgula
            </button>
          </div>
        </form>
      </div>

      {/* ── Ağ Alarmları (IDS) Tablosu ── */}
      {activeTab === "alerts" && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-xs text-gray-500 uppercase tracking-wider border-b border-gray-800 bg-gray-900/50">
                  <th className="px-5 py-3 text-left">Tehdit Türü</th>
                  <th className="px-5 py-3 text-left">Hedef IP</th>
                  <th className="px-5 py-3 text-left">Orijinal MAC</th>
                  <th className="px-5 py-3 text-left">Saldırgan MAC</th>
                  <th className="px-5 py-3 text-left">Tespit Zamanı</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/50">
                {loading ? (
                  <tr>
                    <td colSpan={5} className="px-5 py-12 text-center text-gray-600">
                      <ArrowPathIcon className="w-6 h-6 animate-spin mx-auto mb-2 text-cyan-500" />
                      Loglar yükleniyor...
                    </td>
                  </tr>
                ) : alerts.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="px-5 py-12 text-center text-gray-600">
                      Belirtilen arama kriterlerine uygun kayıt bulunamadı
                    </td>
                  </tr>
                ) : (
                  alerts.map((a) => (
                    <tr key={a.id} className="hover:bg-gray-800/20 transition-colors">
                      <td className="px-5 py-3">
                        <ThreatTypeBadge />
                      </td>
                      <td className="px-5 py-3 font-mono text-xs text-gray-300">
                        {a.target_ip}
                      </td>
                      <td className="px-5 py-3 font-mono text-xs text-gray-400">
                        {a.original_mac}
                      </td>
                      <td className="px-5 py-3 font-mono text-xs text-red-400">
                        {a.attacker_mac}
                      </td>
                      <td className="px-5 py-3 text-xs text-gray-500">
                        {dateFormat(a.created_at)}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
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
                      <ArrowPathIcon className="w-6 h-6 animate-spin mx-auto mb-2 text-cyan-500" />
                      Loglar yükleniyor...
                    </td>
                  </tr>
                ) : urlScans.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="px-5 py-12 text-center text-gray-600">
                      Henüz URL taraması yapılmamış veya filtreye uygun kayıt yok
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
