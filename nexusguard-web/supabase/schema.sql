-- ============================================================
-- NexusGuard IPS — Supabase Veritabanı Şeması
-- Supabase Dashboard → SQL Editor'a yapıştırıp çalıştırın.
-- ============================================================

-- -----------------------------------------------------------
-- 1. TABLO: threat_logs
-- Python IPS motorundan gelen MitM tespiti ve ağ tehdit kayıtları
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.threat_logs (
  id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  -- Tehditin türü: 'ARP_SPOOFING' | 'PORT_SCAN' | 'MITM' | 'DOS'
  threat_type   TEXT        NOT NULL,

  -- Saldırgana ait bilgiler
  attacker_ip   INET,
  attacker_mac  TEXT,

  -- Hedef cihaz bilgileri
  victim_ip     INET,
  victim_mac    TEXT,

  -- Tehdit detayları (JSON olarak ek veriler: paket sayısı, vb.)
  details       JSONB       DEFAULT '{}',

  -- Kill-switch tetiklenip tetiklenmediği
  kill_switch_triggered BOOLEAN DEFAULT FALSE,

  -- Tehditin şu anki durumu
  status        TEXT        NOT NULL DEFAULT 'ACTIVE'
                CHECK (status IN ('ACTIVE', 'MITIGATED', 'INVESTIGATING'))
);

CREATE INDEX IF NOT EXISTS idx_threat_logs_created_at ON public.threat_logs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_threat_logs_status ON public.threat_logs (status);

-- -----------------------------------------------------------
-- 2. TABLO: url_scans
-- Puppeteer ile taranan şüpheli URL'lerin sonuçları
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.url_scans (
  id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  url           TEXT        NOT NULL,

  -- Risk skoru 0-100 arası (0: güvenli, 100: kesinlikle tehlikeli)
  risk_score    SMALLINT    NOT NULL DEFAULT 0
                CHECK (risk_score BETWEEN 0 AND 100),

  verdict       TEXT        NOT NULL DEFAULT 'SAFE'
                CHECK (verdict IN ('SAFE', 'SUSPICIOUS', 'MALICIOUS', 'PHISHING', 'ERROR')),

  -- Puppeteer'in topladığı detaylar (başlıklar, yönlendirmeler, vb.)
  scan_details  JSONB       DEFAULT '{}',

  triggered_by  TEXT        DEFAULT 'MANUAL'
);

CREATE INDEX IF NOT EXISTS idx_url_scans_created_at ON public.url_scans (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_url_scans_verdict ON public.url_scans (verdict);

-- -----------------------------------------------------------
-- 3. TABLO: network_devices
-- Ağda tespit edilen cihazların güncel listesi
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.network_devices (
  id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  first_seen    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen     TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  ip_address    INET        NOT NULL UNIQUE,
  mac_address   TEXT        NOT NULL,
  hostname      TEXT,
  vendor        TEXT,

  is_suspicious BOOLEAN     DEFAULT FALSE,
  is_blocked    BOOLEAN     DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_network_devices_ip ON public.network_devices (ip_address);

-- -----------------------------------------------------------
-- 4. Supabase Realtime etkinleştirme
-- -----------------------------------------------------------
ALTER TABLE public.threat_logs      REPLICA IDENTITY FULL;
ALTER TABLE public.url_scans        REPLICA IDENTITY FULL;
ALTER TABLE public.network_devices  REPLICA IDENTITY FULL;

BEGIN;
  DROP PUBLICATION IF EXISTS supabase_realtime;
  CREATE PUBLICATION supabase_realtime FOR TABLE
    public.threat_logs,
    public.url_scans,
    public.network_devices;
COMMIT;

-- -----------------------------------------------------------
-- 5. Row Level Security (RLS)
-- -----------------------------------------------------------
ALTER TABLE public.threat_logs     ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.url_scans       ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.network_devices ENABLE ROW LEVEL SECURITY;

-- Anonim kullanıcılar okuyabilir (dashboard görüntüleme)
CREATE POLICY "Anon Read: threat_logs"     ON public.threat_logs     FOR SELECT USING (true);
CREATE POLICY "Anon Read: url_scans"       ON public.url_scans       FOR SELECT USING (true);
CREATE POLICY "Anon Read: network_devices" ON public.network_devices  FOR SELECT USING (true);

-- Service role tüm işlemleri yapabilir (Python IPS → webhook üzerinden)
CREATE POLICY "Service Write: threat_logs"     ON public.threat_logs     FOR ALL USING (auth.role() = 'service_role');
CREATE POLICY "Service Write: url_scans"       ON public.url_scans       FOR ALL USING (auth.role() = 'service_role');
CREATE POLICY "Service Write: network_devices" ON public.network_devices  FOR ALL USING (auth.role() = 'service_role');
