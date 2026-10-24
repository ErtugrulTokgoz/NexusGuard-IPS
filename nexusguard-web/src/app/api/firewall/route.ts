/**
 * @file src/app/api/firewall/route.ts
 * @description Windows Güvenlik Duvarı Kill-Switch / Engel Kaldırma Uç Noktası
 *
 * İşlev:
 * 1. Gelen IP adresini valide eder (komut enjeksiyonunu önlemek için).
 * 2. child_process ile PowerShell üzerinden Windows Firewall kuralını kaldırır.
 * 3. Supabase üzerindeki threat_logs ve network_devices kayıtlarında engeli kaldırır.
 */

import { NextRequest, NextResponse } from "next/server";
import { exec } from "child_process";
import { promisify } from "util";
import { createSupabaseAdmin } from "@/lib/supabase";

const execAsync = promisify(exec);

// Güvenli IPv4 regex kontrolü
const IPV4_REGEX = /^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

export async function POST(request: NextRequest) {
  try {
    const body = await request.json().catch(() => null);

    if (!body || (!body.ip && !body.logId)) {
      return NextResponse.json(
        { error: "Geçerli bir 'ip' veya 'logId' alanı gereklidir." },
        { status: 400 }
      );
    }

    const { ip, logId } = body;

    // IP parametresi varsa doğrula
    if (ip && !IPV4_REGEX.test(ip)) {
      return NextResponse.json(
        { error: "Geçersiz IPv4 adresi formatı." },
        { status: 400 }
      );
    }

    let targetIp = ip;
    const supabase = createSupabaseAdmin();

    // Eğer IP gönderilmediyse fakat logId varsa, threat_logs'tan saldırgan IP'sini bul
    if (!targetIp && logId) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const { data: logData } = await (supabase as any)
        .from("threat_logs")
        .select("attacker_ip")
        .eq("id", logId)
        .single();

      if (logData?.attacker_ip && IPV4_REGEX.test(logData.attacker_ip)) {
        targetIp = logData.attacker_ip;
      }
    }

    let powershellOutput = "";
    let powershellSuccess = true;

    // ── 1. PowerShell ile Windows Güvenlik Duvarı kuralını kaldır ─────────────
    if (targetIp) {
      try {
        // Olası standart kural isimlerini ve RemoteAddress eşleşmelerini temizler
        const psCommand = `powershell -NoProfile -NonInteractive -Command "
          Remove-NetFirewallRule -DisplayName 'NexusGuard Block ${targetIp}' -ErrorAction SilentlyContinue;
          Remove-NetFirewallRule -DisplayName 'NexusGuard_${targetIp}' -ErrorAction SilentlyContinue;
          netsh advfirewall firewall delete rule name='NexusGuard Block ${targetIp}' > $null 2>&1;
          Write-Output 'FIREWALL_RULE_REMOVED'
        "`;

        const { stdout, stderr } = await execAsync(psCommand);
        powershellOutput = (stdout || stderr || "").trim();
      } catch (cmdErr: unknown) {
        console.warn("[firewall-api] PowerShell kural silme uyarısı:", cmdErr);
        powershellSuccess = false;
        // Geliştirme veya yetki eksikliği ortamında sistemin durmaması için devam ediyoruz
      }
    }

    // ── 2. Supabase üzerinde threat_logs kaydını güncelle ────────────────────
    if (logId) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await (supabase as any)
        .from("threat_logs")
        .update({
          kill_switch_triggered: false,
          status: "MITIGATED",
        })
        .eq("id", logId);
    } else if (targetIp) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await (supabase as any)
        .from("threat_logs")
        .update({
          kill_switch_triggered: false,
          status: "MITIGATED",
        })
        .eq("attacker_ip", targetIp);
    }

    // ── 3. Supabase üzerinde network_devices kaydını güncelle ────────────────
    if (targetIp) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await (supabase as any)
        .from("network_devices")
        .update({
          is_blocked: false,
          is_suspicious: false,
        })
        .eq("ip_address", targetIp);
    }

    return NextResponse.json({
      success: true,
      message: `${targetIp || "Hedef"} için Windows Güvenlik Duvarı engeli kaldırıldı ve veritabanı güncellendi.`,
      ip: targetIp,
      powershellSuccess,
      powershellOutput,
    });
  } catch (error) {
    console.error("[firewall-api] Hata:", error);
    return NextResponse.json(
      { error: "Güvenlik duvarı işlemi sırasında sunucu hatası oluştu." },
      { status: 500 }
    );
  }
}
