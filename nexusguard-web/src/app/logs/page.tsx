/**
 * @file src/app/logs/page.tsx
 * @description NexusGuard IPS — Güvenlik Logları Sayfası
 *
 * Özellikler:
 * - Supabase üzerinde çalışan IP adresi ve Tarih (Başlangıç/Bitiş) bazlı gelişmiş filtreleme
 * - MitM/ARP saldırı logları (threat_logs tablosu)
 * - Taranan URL sonuçları (url_scans tablosu)
 * - İnteraktif Kill-Switch: Kırmızı 'Aktif' butonuna basıldığında Windows Firewall engelini kaldırır
 * - Supabase Realtime ile canlı güncelleme
 */

"use client";

import { useState, useEffect, useCallback } from "react";
import { createSupabaseClient, ThreatLog, UrlScan } from "@/lib/supabase";
import {
  ShieldExclamationIcon,
  LinkIcon,
  FunnelIcon,
  MagnifyingGlassIcon,
  CalendarDaysIcon,
  ArrowPathIcon,
  XMarkIcon,
  CheckCircleIcon,
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
    <span
      className={`px-2 py-1 rounded-full text-xs font-medium ${
        colors[status] ?? "text-gray-400"
      }`}
    >
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

  // Filtreleme Durumları (Supabase üzerinde sorgulanır)
  const [ipFilter, setIpFilter] = useState("");
  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");
  const [selectedThreatType, setSelectedThreatType] = useState("ALL");

  // Kill-Switch engel kaldırma durumları
  const [unblockingIds, setUnblockingIds] = useState<Record<string, boolean>>({});
  const [notification, setNotification] = useState<{
    type: "success" | "error";
    message: string;
  } | null>(null);

  const THREAT_TYPES = ["ALL", "ARP_SPOOFING", "MITM", "PORT_SCAN", "DOS"];

  // ── Supabase Verilerini Filtre ile Çek ────────────────────────────────
  const fetchLogs = useCallback(
    async (overrideFilters?: {
      ip?: string;
      start?: string;
      end?: string;
      type?: string;
    }) => {
      const supabase = createSupabaseClient();
      setLoading(true);

      const targetIp = overrideFilters?.ip !== undefined ? overrideFilters.ip : ipFilter;
      const targetStart = overrideFilters?.start !== undefined ? overrideFilters.start : startDate;
      const targetEnd = overrideFilters?.end !== undefined ? overrideFilters.end : endDate;
      const targetType = overrideFilters?.type !== undefined ? overrideFilters.type : selectedThreatType;

      try {
        // 1. Threat Logs Sorgusu
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        let threatQuery = (supabase as any)
          .from("threat_logs")
          .select("*")
          .order("created_at", { ascending: false })
          .limit(100);

        // Tehdit Türü Filtresi
        if (targetType && targetType !== "ALL") {
          threatQuery = threatQuery.eq("threat_type", targetType);
        }

        // IP Adresi Filtresi (Saldırgan veya Hedef IP)
        if (targetIp.trim()) {
          const cleanIp = targetIp.trim();
          threatQuery = threatQuery.or(`attacker_ip.ilike.%${cleanIp}%,victim_ip.ilike.%${cleanIp}%`);
        }

        // Başlangıç Tarihi Filtresi
        if (targetStart) {
          const startIso = new Date(targetStart).toISOString();
          threatQuery = threatQuery.gte("created_at", startIso);
        }

        // Bitiş Tarihi Filtresi (Gün sonu 23:59:59)
        if (targetEnd) {
          const endObj = new Date(targetEnd);
          endObj.setHours(23, 59, 59, 999);
          threatQuery = threatQuery.lte("created_at", endObj.toISOString());
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

        const [threatRes, scanRes] = await Promise.all([threatQuery, scanQuery]);

        if (threatRes.data) setThreats(threatRes.data);
        if (scanRes.data) setUrlScans(scanRes.data);
      } catch (err) {
        console.error("[logs] Veri çekme hatası:", err);
      } finally {
        setLoading(false);
      }
    },
    [ipFilter, startDate, endDate, selectedThreatType]
  );

  // ── İlk Yükleme ve Realtime Aboneliği ──────────────────────────────────
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
      .on(
        "postgres_changes",
        { event: "UPDATE", schema: "public", table: "threat_logs" },
        (payload) => {
          const updated = payload.new as ThreatLog;
          setThreats((prev) =>
            prev.map((t) => (t.id === updated.id ? updated : t))
          );
        }
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

  // ── Filtreleri Sıfırla ────────────────────────────────────────────────
  const handleResetFilters = () => {
    setIpFilter("");
    setStartDate("");
    setEndDate("");
    setSelectedThreatType("ALL");
    fetchLogs({ ip: "", start: "", end: "", type: "ALL" });
  };

  // ── Kill-Switch Engel Kaldırma (Firewall API) ─────────────────────────
  const handleUnblockKillSwitch = async (logId: string, attackerIp: string | null) => {
    if (unblockingIds[logId]) return;

    const confirmed = window.confirm(
      `${attackerIp || "Bu cihaz"} için uygulanan Windows Güvenlik Duvarı Kill-Switch engelini kaldırmak istiyor musunuz?`
    );
    if (!confirmed) return;

    setUnblockingIds((prev) => ({ ...prev, [logId]: true }));
    setNotification(null);

    try {
      const res = await fetch("/api/firewall", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ logId, ip: attackerIp }),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || "Engel kaldırma işlemi başarısız oldu.");
      }

      // Yerel state'i güncelle
      setThreats((prev) =>
        prev.map((t) =>
          t.id === logId
            ? { ...t, kill_switch_triggered: false, status: "MITIGATED" }
            : t
        )
      );

      setNotification({
        type: "success",
        message: data.message || "Windows Güvenlik Duvarı engeli başarıyla kaldırıldı.",
      });

      setTimeout(() => setNotification(null), 4000);
    } catch (err: unknown) {
      console.error("[logs-unblock] Hata:", err);
      setNotification({
        type: "error",
        message: err instanceof Error ? err.message : "İşlem sırasında hata oluştu.",
      });
    } finally {
      setUnblockingIds((prev) => ({ ...prev, [logId]: false }));
    }
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

  const isFilterActive =
    Boolean(ipFilter.trim()) ||
    Boolean(startDate) ||
    Boolean(endDate) ||
    selectedThreatType !== "ALL";

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">

      {/* ── Bildirim Alanı ── */}
      {notification && (
        <div
          className={`flex items-center justify-between px-4 py-3 rounded-xl border text-sm transition-all ${
            notification.type === "success"
              ? "bg-green-500/10 border-green-500/30 text-green-300"
              : "bg-red-500/10 border-red-500/30 text-red-300"
          }`}
        >
          <div className="flex items-center gap-2">
            <CheckCircleIcon className="w-5 h-5 flex-shrink-0" />
            <span>{notification.message}</span>
          </div>
          <button
            onClick={() => setNotification(null)}
            className="text-xs opacity-75 hover:opacity-100 underline ml-4"
          >
            Kapat
          </button>
        </div>
      )}

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
            { id: "threats", label: "Tehdit Logları", icon: ShieldExclamationIcon, count: threats.length },
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

      {/* ── Gelişmiş Filtreleme Bölümü (Supabase Sorgusu) ── */}
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
          className="grid grid-cols-1 md:grid-cols-12 gap-3"
        >
          {/* IP Adresi Arama */}
          <div className="md:col-span-4 relative">
            <label className="block text-xs font-medium text-gray-400 mb-1">
              IP Adresi (Saldırgan / Hedef)
            </label>
            <div className="relative">
              <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
              <input
                type="text"
                placeholder="Örn: 192.168.1.105"
                value={ipFilter}
                onChange={(e) => setIpFilter(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg pl-9 pr-3 py-2 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          {/* Başlangıç Tarihi */}
          <div className="md:col-span-3">
            <label className="block text-xs font-medium text-gray-400 mb-1">
              Başlangıç Tarihi
            </label>
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
          <div className="md:col-span-3">
            <label className="block text-xs font-medium text-gray-400 mb-1">
              Bitiş Tarihi
            </label>
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

        {/* Tehdit Türü Hızlı Filtre Butonları */}
        {activeTab === "threats" && (
          <div className="pt-2 border-t border-gray-800/80 flex items-center gap-2 flex-wrap text-xs">
            <span className="text-gray-500">Tehdit Türü:</span>
            {THREAT_TYPES.map((type) => (
              <button
                key={type}
                onClick={() => {
                  setSelectedThreatType(type);
                  fetchLogs({ type });
                }}
                className={`px-2.5 py-1 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
                  selectedThreatType === type
                    ? "bg-cyan-500/15 text-cyan-400 border border-cyan-500/30"
                    : "text-gray-400 hover:text-gray-200 hover:bg-gray-800"
                }`}
              >
                {type}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* ── Tehdit Logları Tablosu ── */}
      {activeTab === "threats" && (
        <div className="space-y-4">
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
                        <ArrowPathIcon className="w-6 h-6 animate-spin mx-auto mb-2 text-cyan-500" />
                        Loglar yükleniyor...
                      </td>
                    </tr>
                  ) : threats.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="px-5 py-12 text-center text-gray-600">
                        Belirtilen arama kriterlerine uygun kayıt bulunamadı
                      </td>
                    </tr>
                  ) : (
                    threats.map((t) => (
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
                            <button
                              onClick={() => handleUnblockKillSwitch(t.id, t.attacker_ip)}
                              disabled={unblockingIds[t.id]}
                              title="Windows Güvenlik Duvarı engelini kaldırmak için tıklayın"
                              className="group inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-red-500/15 text-red-400 border border-red-500/40 hover:bg-red-500/25 hover:border-red-400 hover:text-red-300 transition-all cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed shadow-sm"
                            >
                              {unblockingIds[t.id] ? (
                                <>
                                  <ArrowPathIcon className="w-3.5 h-3.5 animate-spin text-red-400" />
                                  <span>Kaldırılıyor...</span>
                                </>
                              ) : (
                                <>
                                  <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse group-hover:scale-125 transition-transform" />
                                  <span>Aktif (Kaldır)</span>
                                </>
                              )}
                            </button>
                          ) : (
                            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs text-gray-400 bg-gray-800/50 border border-gray-700/50">
                              <span className="w-1.5 h-1.5 rounded-full bg-gray-500" />
                              <span>Pasif</span>
                            </span>
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
