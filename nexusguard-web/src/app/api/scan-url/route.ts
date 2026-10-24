import { NextRequest, NextResponse } from "next/server";
import { analyzeUrl } from "@/lib/risk-analyzer";
import { createSupabaseAdmin } from "@/lib/supabase";

export const maxDuration = 30;

export async function POST(request: NextRequest) {
  try {
    const body = await request.json().catch(() => null);
    if (!body || typeof body.url !== "string" || !body.url.trim()) {
      return NextResponse.json({ error: "Geçerli bir 'url' alanı gereklidir." }, { status: 400 });
    }
    const targetUrl = body.url.trim();

    // 1. Google Safe Browsing Taraması
    const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
    const googleApiUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;
    const googleRes = await fetch(googleApiUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client: { clientId: "nexusguard", clientVersion: "1.0.0" },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url: targetUrl }]
        }
      })
    });
    const googleData = await googleRes.json();
    const isGoogleThreat = googleData.matches ? true : false;

    // 2. Puppeteer Risk Analizi
    const scanResult = await analyzeUrl(targetUrl);

    // 3. Sonuçları Birleştir ve Güncelle
    scanResult.scan_details = {
      ...scanResult.scan_details,
      googleSafeBrowsing: isGoogleThreat ? "TEHDİT ALGILANDI" : "GÜVENLİ",
      googleMatches: googleData.matches || []
    };

    if (isGoogleThreat) {
      scanResult.risk_score = 100; // Google tehdit bulursa skoru direkt tavan yap
      scanResult.verdict = "MALICIOUS";
    }

    // 4. Supabase'e Kaydet
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

    if (error) console.error("[scan-url] Supabase kayıt hatası:", error);

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