/**
 * @file risk-analyzer.ts
 * @description Puppeteer tabanlı URL risk analiz motoru (Vercel Uyumlu).
 */

import puppeteer from 'puppeteer-core';
import chromium from '@sparticuz/chromium';

/** Tarama sonuç tipi */
export interface ScanResult {
  url: string;
  risk_score: number;
  verdict: "SAFE" | "SUSPICIOUS" | "MALICIOUS" | "PHISHING" | "ERROR";
  scan_details: {
    final_url: string;
    redirect_count: number;
    page_title: string;
    has_password_field: boolean;
    has_suspicious_keywords: boolean;
    suspicious_keywords_found: string[];
    response_status: number | null;
    scan_duration_ms: number;
  };
}

/** Oltalama sitelerinde sık karşılaşılan anahtar kelimeler */
const PHISHING_KEYWORDS = [
  "verify your account",
  "confirm your identity",
  "update your payment",
  "suspended account",
  "unusual activity",
  "click here to verify",
  "account will be closed",
  "hesabınız askıya alındı",
  "bilgilerinizi doğrulayın",
  "ödeme bilgilerinizi güncelleyin",
  "şifrenizi sıfırlayın",
  "güvenlik uyarısı",
];

/**
 * Verilen URL'yi Puppeteer ile tarar ve risk analizi yapar.
 * @param targetUrl - Taranacak URL (http/https ile başlamalı)
 * @returns ScanResult nesnesi
 */
export async function analyzeUrl(targetUrl: string): Promise<ScanResult> {
  const startTime = Date.now();
  const timeout = parseInt(process.env.SCAN_TIMEOUT_MS ?? "10000", 10);

  // URL doğrulama
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(targetUrl);
    if (!["http:", "https:"].includes(parsedUrl.protocol)) {
      throw new Error("Geçersiz protokol");
    }
  } catch {
    return buildErrorResult(targetUrl);
  }

  let browser;
  try {
    // Vercel Serverless ortamına uygun Chromium başlatma
    browser = await puppeteer.launch({
      args: chromium.args,
      executablePath: await chromium.executablePath(),
      headless: true,
      ignoreHTTPSErrors: true,
    } as any);

    const page = await browser.newPage();

    // Zaman aşımı ve User-Agent ayarı
    page.setDefaultNavigationTimeout(timeout);
    await page.setUserAgent(
      "Mozilla/5.0 (compatible; NexusGuard-Scanner/1.0; +https://nexusguard.local)"
    );

    // Yönlendirme zinciri takibi
    const redirects: string[] = [];
    page.on("response", (response) => {
      if ([301, 302, 303, 307, 308].includes(response.status())) {
        redirects.push(response.url());
      }
    });

    // Sayfayı yükle
    let responseStatus: number | null = null;
    try {
      const response = await page.goto(parsedUrl.href, {
        waitUntil: "domcontentloaded",
      });
      responseStatus = response?.status() ?? null;
    } catch {
      // Zaman aşımı veya bağlantı hatası — sonuç oluşturmaya devam et
    }

    const finalUrl = page.url();
    const pageTitle = await page.title().catch(() => "");

    // Şifre alanı var mı?
    const hasPasswordField = await page
      .$$eval('input[type="password"]', (els) => els.length > 0)
      .catch(() => false);

    // Oltalama anahtar kelime taraması
    const pageText = await page
      .evaluate(() => document.body?.innerText?.toLowerCase() ?? "")
      .catch(() => "");

    const suspiciousKeywordsFound = PHISHING_KEYWORDS.filter((kw) =>
      pageText.includes(kw.toLowerCase())
    );

    await browser.close();
    browser = undefined;

    // ── Risk Puanı Hesaplama ──────────────────────────────────────────────
    let riskScore = 0;

    // Birden fazla yönlendirme şüpheli
    riskScore += Math.min(redirects.length * 10, 30);

    // Şifre alanı + yönlendirme = klasik oltalama işareti
    if (hasPasswordField && redirects.length > 0) riskScore += 25;
    else if (hasPasswordField) riskScore += 10;

    // Oltalama anahtar kelimeleri
    riskScore += Math.min(suspiciousKeywordsFound.length * 15, 40);

    // Nihai URL orijinalden farklıysa şüpheli
    if (finalUrl !== parsedUrl.href && !finalUrl.startsWith(parsedUrl.origin)) {
      riskScore += 20;
    }

    riskScore = Math.min(riskScore, 100);

    // Karar
    const verdict =
      riskScore >= 70
        ? "PHISHING"
        : riskScore >= 50
        ? "MALICIOUS"
        : riskScore >= 25
        ? "SUSPICIOUS"
        : "SAFE";

    return {
      url: targetUrl,
      risk_score: riskScore,
      verdict,
      scan_details: {
        final_url: finalUrl,
        redirect_count: redirects.length,
        page_title: pageTitle,
        has_password_field: hasPasswordField,
        has_suspicious_keywords: suspiciousKeywordsFound.length > 0,
        suspicious_keywords_found: suspiciousKeywordsFound,
        response_status: responseStatus,
        scan_duration_ms: Date.now() - startTime,
      },
    };
  } catch (error) {
    if (browser) await browser.close().catch(() => {});
    console.error("[risk-analyzer] Tarama hatası:", error);
    return buildErrorResult(targetUrl);
  }
}

/** Hata durumunda döndürülecek varsayılan sonuç */
function buildErrorResult(url: string): ScanResult {
  return {
    url,
    risk_score: 0,
    verdict: "ERROR",
    scan_details: {
      final_url: url,
      redirect_count: 0,
      page_title: "",
      has_password_field: false,
      has_suspicious_keywords: false,
      suspicious_keywords_found: [],
      response_status: null,
      scan_duration_ms: 0,
    },
  };
}
