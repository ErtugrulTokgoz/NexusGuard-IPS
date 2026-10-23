/**
 * @file src/app/page.tsx
 * @description NexusGuard IPS — Ana Dashboard Sayfası
 *
 * Özellikler:
 * - Büyük URL tarama çubuğu (/api/scan-url'e POST atar)
 * - Anlık istatistik kartları (toplam tehdit, aktif cihaz, taranan URL)
 * - Son tehditler ve son URL taramalarının özet tabloları
 * - Supabase Realtime ile otomatik canlı güncelleme
 */

"use client";

import { useState, useEffect, useCallback } from "react";
import { createSupabaseClient, ThreatLog, UrlScan } from "@/lib/supabase";
import {
  ShieldExclamationIcon,
  MagnifyingGlassIcon,
  WifiIcon,
  ClockIcon,
  ArrowPathIcon,
} from "@heroicons/react/24/outline";

// ── Alt Bileşen: İstatistik Kartı ─────────────────────────────────────────

function StatCard({
  title,
  value,
  subtitle,
  icon: Icon,
  color,
}: {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: React.ElementType;
  color: "cyan" | "red" | "green" | "yellow";
}) {
  const colorMap = {
    cyan: "text-cyan-400 bg-cyan-400/10 border-cyan-500/20",
    red: "text-red-400 bg-red-400/10 border-red-500/20",
    green: "text-green-400 bg-green-400/10 border-green-500/20",
    yellow: "text-yellow-400 bg-yellow-400/10 border-yellow-500/20",
  };

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 hover:border-gray-700 transition-colors">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-medium text-gray-500 uppercase tracking-wider">
            {title}
          </p>
          <p className="text-3xl font-bold text-white mt-1">{value}</p>
          {subtitle && <p className="text-xs text-gray-500 mt-1">{subtitle}</p>}
        </div>
        <div className={`p-2.5 rounded-lg border ${colorMap[color]}`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
    </div>
  );
}

// ── Alt Bileşen: Risk Skoru Rozeti ───────────────────────────────────────

function RiskBadge({ score, verdict }: { score: number; verdict: string }) {
  const color =
    score >= 70
      ? "bg-red-500/10 text-red-400 border-red-500/30"
      : score >= 25
      ? "bg-yellow-500/10 text-yellow-400 border-yellow-500/30"
      : "bg-green-500/10 text-green-400 border-green-500/30";

  return (
    <span className={`px-2 py-1 rounded-full text-xs font-medium border ${color}`}>
      {verdict} · {score}/100
    </span>
  );
}

// ── Ana Sayfa Bileşeni ────────────────────────────────────────────────────

export default function DashboardPage() {
  const [scanUrl, setScanUrl] = useState("");
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<null | {
    risk_score: number;
    verdict: string;
    scan_details: Record<string, unknown>;
  }>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  const [threats, setThreats] = useState<ThreatLog[]>([]);
  const [urlScans, setUrlScans] = useState<UrlScan[]>([]);
  const [deviceCount, setDeviceCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [currentTime, setCurrentTime] = useState("");

  // ── İlk veri yükleme ─────────────────────────────────────────────────
  const fetchInitialData = useCallback(async () => {
    const supabase = createSupabaseClient();

    const [threatRes, scanRes, deviceRes] = await Promise.all([
      supabase
        .from("threat_logs")
        .select("*")
        .order("created_at", { ascending: false })
        .limit(5),
      supabase
        .from("url_scans")
        .select("*")
        .order("created_at", { ascending: false })
        .limit(5),
      supabase
        .from("network_devices")
        .select("id", { count: "exact", head: true }),
    ]);

    if (threatRes.data) setThreats(threatRes.data);
    if (scanRes.data) setUrlScans(scanRes.data);
    if (deviceRes.count !== null) setDeviceCount(deviceRes.count);
    setLoading(false);
  }, []);

  // ── Supabase Realtime aboneliği ───────────────────────────────────────
  useEffect(() => {
    fetchInitialData();
    const supabase = createSupabaseClient();

    // Yeni tehdit geldiğinde listeye ekle (en başa)
    const threatSub = supabase
      .channel("dashboard-threats")
      .on(
        "postgres_changes",
        { event: "INSERT", schema: "public", table: "threat_logs" },
        (payload) => {
          setThreats((prev) => [payload.new as ThreatLog, ...prev.slice(0, 4)]);
        }
      )
      .subscribe();

    // Yeni URL taraması geldiğinde listeye ekle
    const scanSub = supabase
      .channel("dashboard-scans")
      .on(
        "postgres_changes",
        { event: "INSERT", schema: "public", table: "url_scans" },
        (payload) => {
          setUrlScans((prev) => [payload.new as UrlScan, ...prev.slice(0, 4)]);
        }
      )
      .subscribe();

    return () => {
      supabase.removeChannel(threatSub);
      supabase.removeChannel(scanSub);
    };
  }, [fetchInitialData]);

  // ── URL Tarama ────────────────────────────────────────────────────────
  const handleScan = async () => {
    if (!scanUrl.trim() || scanning) return;
    setScanResult(null);
    setScanError(null);
    setScanning(true);

    try {
      const res = await fetch("/api/scan-url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: scanUrl.trim() }),
      });
      const data = await res.json();

      if (!res.ok) {
        setScanError(data.error ?? "Tarama başarısız oldu.");
      } else {
        setScanResult(data);
      }
    } catch {
      setScanError("Sunucuya ulaşılamadı. Lütfen tekrar deneyin.");
    } finally {
      setScanning(false);
    }
  };

  // ── Render ────────────────────────────────────────────────────────────
  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">

      {/* ── Sayfa Başlığı ── */}
      <div>
        <h1 className="text-2xl font-bold text-white">Güvenlik Dashboard&apos;u</h1>
        <p className="text-sm text-gray-500 mt-1">
          Ağınızdaki tehditleri gerçek zamanlı olarak izleyin
        </p>
      </div>

      {/* ── URL Tarama Çubuğu ── */}
      <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6 space-y-4">
        <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">
          Şüpheli URL Analizi
        </h2>

        <div className="flex gap-3">
          <div className="relative flex-1">
            <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
            <input
              type="url"
              value={scanUrl}
              onChange={(e) => setScanUrl(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleScan()}
              placeholder="https://şüpheli-site.com adresini yapıştırın..."
              className="w-full bg-gray-800 border border-gray-700 rounded-xl pl-10 pr-4 py-3 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition"
            />
          </div>
          <button
            onClick={handleScan}
            disabled={scanning || !scanUrl.trim()}
            className="px-6 py-3 bg-cyan-500 hover:bg-cyan-400 disabled:bg-gray-700 disabled:cursor-not-allowed text-gray-950 font-semibold rounded-xl text-sm transition-colors flex items-center gap-2"
          >
            {scanning ? (
              <>
                <ArrowPathIcon className="w-4 h-4 animate-spin" />
                Taranıyor...
              </>
            ) : (
              "Tara"
            )}
          </button>
        </div>

        {/* Tarama Sonucu Kartı */}
        {scanResult && (
          <div className="p-4 bg-gray-800/60 rounded-xl border border-gray-700 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium text-white">Tarama Sonucu</span>
              <RiskBadge score={scanResult.risk_score} verdict={scanResult.verdict} />
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs text-gray-400">
              <div>
                <span className="block text-gray-600">Yönlendirme</span>
                <span className="text-white font-medium">
                  {String(scanResult.scan_details?.redirect_count ?? 0)}x
                </span>
              </div>
              <div>
                <span className="block text-gray-600">Şifre Alanı</span>
                <span
                  className={
                    scanResult.scan_details?.has_password_field
                      ? "text-red-400 font-medium"
                      : "text-white font-medium"
                  }
                >
                  {scanResult.scan_details?.has_password_field ? "Var ⚠" : "Yok"}
                </span>
              </div>
              <div>
                <span className="block text-gray-600">Risk Skoru</span>
                <span className="text-white font-medium">{scanResult.risk_score}/100</span>
              </div>
              <div>
                <span className="block text-gray-600">Tarama Süresi</span>
                <span className="text-white font-medium">
                  {String(scanResult.scan_details?.scan_duration_ms ?? 0)}ms
                </span>
              </div>
            </div>
          </div>
        )}

        {/* Hata Mesajı */}
        {scanError && (
          <p className="text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-4 py-2">
            {scanError}
          </p>
        )}
      </div>

      {/* ── İstatistik Kartları ── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Toplam Tehdit"
          value={loading ? "—" : threats.length}
          subtitle="Son 5 kayıt"
          icon={ShieldExclamationIcon}
          color="red"
        />
        <StatCard
          title="Aktif Cihaz"
          value={loading ? "—" : deviceCount}
          subtitle="Ağda tespit edilen"
          icon={WifiIcon}
          color="cyan"
        />
        <StatCard
          title="Taranan URL"
          value={loading ? "—" : urlScans.length}
          subtitle="Son 5 tarama"
          icon={MagnifyingGlassIcon}
          color="green"
        />
        <StatCard
          title="Son Güncelleme"
          value={loading ? "—" : "Canlı"}
          subtitle="Realtime aktif"
          icon={ClockIcon}
          color="yellow"
        />
      </div>

      {/* ── Son Tehditler Tablosu ── */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-800 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-white">Son Tehditler</h2>
          <span className="text-xs text-gray-600">Canlı güncelleme</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-xs text-gray-500 uppercase tracking-wider border-b border-gray-800">
                <th className="px-5 py-3 text-left">Tür</th>
                <th className="px-5 py-3 text-left">Saldırgan IP</th>
                <th className="px-5 py-3 text-left">Hedef IP</th>
                <th className="px-5 py-3 text-left">Kill-Switch</th>
                <th className="px-5 py-3 text-left">Tarih</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={5} className="px-5 py-8 text-center text-gray-600">
                    Yükleniyor...
                  </td>
                </tr>
              ) : threats.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-5 py-8 text-center text-gray-600">
                    Henüz tehdit kaydı yok — Python motoru bağlanınca görünecek
                  </td>
                </tr>
              ) : (
                threats.map((t) => (
                  <tr
                    key={t.id}
                    className="border-b border-gray-800/50 hover:bg-gray-800/30 transition-colors"
                  >
                    <td className="px-5 py-3">
                      <span className="px-2 py-1 rounded text-xs font-mono font-medium bg-red-500/10 text-red-400 border border-red-500/20">
                        {t.threat_type}
                      </span>
                    </td>
                    <td className="px-5 py-3 font-mono text-xs text-gray-300">
                      {t.attacker_ip ?? "—"}
                    </td>
                    <td className="px-5 py-3 font-mono text-xs text-gray-300">
                      {t.victim_ip ?? "—"}
                    </td>
                    <td className="px-5 py-3">
                      {t.kill_switch_triggered ? (
                        <span className="text-xs text-red-400 font-medium">● Aktif</span>
                      ) : (
                        <span className="text-xs text-gray-600">○ Hayır</span>
                      )}
                    </td>
                    <td className="px-5 py-3 text-xs text-gray-500">
                      {new Date(t.created_at).toLocaleString("tr-TR")}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
