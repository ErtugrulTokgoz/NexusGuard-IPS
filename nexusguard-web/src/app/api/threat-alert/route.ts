/**
 * @file src/app/api/threat-alert/route.ts
 * @description POST /api/threat-alert — Python IPS motoru webhook uç noktası.
 *
 * Python (Scapy) motoru bir tehdit tespit ettiğinde bu uç noktaya POST atar.
 * İstek başlığında "x-ips-secret" ile kimlik doğrulaması yapılır.
 *
 * Python'dan beklenen istek örneği:
 * ```python
 * import requests
 * requests.post(
 *   "http://localhost:3000/api/threat-alert",
 *   headers={"x-ips-secret": "nexusguard_super_secret_2024"},
 *   json={
 *     "threat_type": "ARP_SPOOFING",
 *     "attacker_ip": "192.168.1.105",
 *     "attacker_mac": "aa:bb:cc:dd:ee:ff",
 *     "victim_ip": "192.168.1.1",
 *     "victim_mac": "11:22:33:44:55:66",
 *     "kill_switch_triggered": True,
 *     "details": { "packet_count": 150, "interface": "eth0" }
 *   }
 * )
 * ```
 */

import { NextRequest, NextResponse } from "next/server";
import { createSupabaseAdmin } from "@/lib/supabase";

const ALLOWED_THREAT_TYPES = ["ARP_SPOOFING", "PORT_SCAN", "MITM", "DOS"] as const;

export async function POST(request: NextRequest) {
  // ── Webhook gizli anahtar doğrulama ──────────────────────────────────
  const secret = request.headers.get("x-ips-secret");
  const expectedSecret = process.env.IPS_WEBHOOK_SECRET;

  if (!secret || secret !== expectedSecret) {
    return NextResponse.json(
      { error: "Yetkisiz erişim. Geçerli 'x-ips-secret' başlığı gereklidir." },
      { status: 401 }
    );
  }

  try {
    const body = await request.json();

    // ── Giriş doğrulama ───────────────────────────────────────────────
    if (!body.threat_type || !ALLOWED_THREAT_TYPES.includes(body.threat_type)) {
      return NextResponse.json(
        {
          error: `Geçersiz threat_type. İzin verilenler: ${ALLOWED_THREAT_TYPES.join(", ")}`,
        },
        { status: 400 }
      );
    }

    // ── Supabase'e tehdit kaydı ekle ──────────────────────────────────
    const supabase = createSupabaseAdmin();

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const threatResult = await (supabase as any)
      .from("threat_logs")
      .insert({
        threat_type: body.threat_type,
        attacker_ip: body.attacker_ip ?? null,
        attacker_mac: body.attacker_mac ?? null,
        victim_ip: body.victim_ip ?? null,
        victim_mac: body.victim_mac ?? null,
        details: body.details ?? {},
        kill_switch_triggered: body.kill_switch_triggered ?? false,
        status: "ACTIVE",
      })
      .select("id, created_at")
      .single();

    const data: { id: string; created_at: string } | null = threatResult.data;
    const error: unknown = threatResult.error;

    if (error) {
      console.error("[threat-alert] Supabase yazma hatası:", error);
      return NextResponse.json({ error: "Veritabanı hatası." }, { status: 500 });
    }

    // ── Saldırgana ait cihazı güncelle / ekle ─────────────────────────
    if (body.attacker_ip && body.attacker_mac) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await (supabase as any).from("network_devices").upsert(
        {
          ip_address: body.attacker_ip,
          mac_address: body.attacker_mac,
          last_seen: new Date().toISOString(),
          is_suspicious: true,
          is_blocked: body.kill_switch_triggered ?? false,
        },
        { onConflict: "ip_address" }
      );
    }

    console.log(
      `[threat-alert] Tehdit kaydedildi: ${data!.id} (${body.threat_type})`
    );

    return NextResponse.json({
      success: true,
      log_id: data!.id,
      created_at: data!.created_at,
      message: "Tehdit başarıyla kaydedildi.",
    });
  } catch (error) {
    console.error("[threat-alert] Beklenmeyen hata:", error);
    return NextResponse.json({ error: "Sunucu hatası." }, { status: 500 });
  }
}
