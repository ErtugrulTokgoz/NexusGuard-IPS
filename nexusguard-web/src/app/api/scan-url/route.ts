/**
 * @file src/app/api/scan-url/route.ts
 * @description POST /api/scan-url — Şüpheli URL tarama uç noktası.
 *
 * İstek gövdesi: { "url": "https://example.com" }
 * Yanıt: ScanResult + Supabase kayıt ID'si
 *
 * Dashboard'daki arama çubuğundan tetiklenir.
 * Puppeteer ile tarar, Supabase url_scans tablosuna kaydeder.
 */

import { NextRequest, NextResponse } from "next/server";
import { analyzeUrl } from "@/lib/risk-analyzer";
import { createSupabaseAdmin } from "@/lib/supabase";

export const maxDuration = 30; // Vercel Pro'da 30sn zaman aşımı

export async function POST(request: NextRequest) {
  try {
    // ── Gelen isteği ayrıştır ──────────────────────────────────────────
    const body = await request.json().catch(() => null);

    if (!body || typeof body.url !== "string" || !body.url.trim()) {
      return NextResponse.json(
        { error: "Geçerli bir 'url' alanı gereklidir." },
        { status: 400 }
      );
    }

    const targetUrl = body.url.trim();

    // ── Puppeteer ile risk analizi yap ────────────────────────────────
    const scanResult = await analyzeUrl(targetUrl);

    // ── Sonucu Supabase'e kaydet ──────────────────────────────────────
    const supabase = createSupabaseAdmin();

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const insertResult = await (supabase as any)
      .from("url_scans")
      .insert({
        url: scanResult.url,
        risk_score: scanResult.risk_score,
        verdict: scanResult.verdict,
        scan_details: scanResult.scan_details,
        triggered_by: "MANUAL_DASHBOARD",
      })
      .select("id")
      .single();

    const data: { id: string } | null = insertResult.data;
    const error: unknown = insertResult.error;

    if (error) {
      // Kayıt başarısız olsa bile tarama sonucunu döndür
      console.error("[scan-url] Supabase kayıt hatası:", error);
    }

    return NextResponse.json({
      success: true,
      scan_id: data?.id ?? null,
      ...scanResult,
    });
  } catch (error) {
    console.error("[scan-url] Beklenmeyen hata:", error);
    return NextResponse.json(
      { error: "Sunucu hatası oluştu. Lütfen tekrar deneyin." },
      { status: 500 }
    );
  }
}
