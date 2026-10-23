/**
 * @file src/app/api/devices/route.ts
 * @description GET/POST /api/devices — Ağ cihazları uç noktası.
 *
 * GET:  Tüm tespit edilen cihazları döndürür (Topoloji sayfası için).
 * POST: Python motorundan gelen cihaz listesini toplu günceller.
 *
 * POST için "x-ips-secret" header zorunludur.
 */

import { NextRequest, NextResponse } from "next/server";
import { createSupabaseAdmin, type Database } from "@/lib/supabase";

type DeviceInsert = Database["public"]["Tables"]["network_devices"]["Insert"];

/** GET: Ağdaki tüm cihazları listele */
export async function GET() {
  const supabase = createSupabaseAdmin();

  const { data, error } = await supabase
    .from("network_devices")
    .select("*")
    .order("last_seen", { ascending: false });

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  return NextResponse.json({ devices: data });
}

/** POST: Python motorundan toplu cihaz listesi güncelleme */
export async function POST(request: NextRequest) {
  // Webhook güvenliği
  const secret = request.headers.get("x-ips-secret");
  if (secret !== process.env.IPS_WEBHOOK_SECRET) {
    return NextResponse.json({ error: "Yetkisiz." }, { status: 401 });
  }

  const body = await request.json();
  const devices: Array<{
    ip_address: string;
    mac_address: string;
    hostname?: string;
    vendor?: string;
  }> = body.devices ?? [];

  if (!Array.isArray(devices) || devices.length === 0) {
    return NextResponse.json(
      { error: "devices dizisi gereklidir." },
      { status: 400 }
    );
  }

  const supabase = createSupabaseAdmin();

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const rows = devices.map((d) => ({
    ip_address: d.ip_address,
    mac_address: d.mac_address,
    hostname: d.hostname ?? null,
    vendor: d.vendor ?? null,
    last_seen: new Date().toISOString(),
    is_suspicious: false,
    is_blocked: false,
  })) as DeviceInsert[];

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { error } = await (supabase as any)
    .from("network_devices")
    .upsert(rows, { onConflict: "ip_address" });

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  return NextResponse.json({ success: true, updated: devices.length });
}
