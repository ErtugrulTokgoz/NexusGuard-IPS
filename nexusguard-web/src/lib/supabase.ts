/**
 * @file supabase.ts
 * @description Supabase istemci fabrikaları.
 * - createSupabaseClient: Tarayıcı tarafı (anon key, Realtime destekli)
 * - createSupabaseAdmin:  Sunucu tarafı (service_role, tam erişim)
 *
 * Next.js App Router'da Server Component'ler ve API Route'lar
 * createSupabaseAdmin kullanmalı; Client Component'ler createSupabaseClient kullanmalı.
 */

import { createClient, SupabaseClient } from "@supabase/supabase-js";

// ── Tip tanımları ──────────────────────────────────────────────────────────

/** threat_logs tablosu için TypeScript arayüzü */
export interface ThreatLog {
  id: string;
  created_at: string;
  threat_type: "ARP_SPOOFING" | "PORT_SCAN" | "MITM" | "DOS";
  attacker_ip: string | null;
  attacker_mac: string | null;
  victim_ip: string | null;
  victim_mac: string | null;
  details: Record<string, unknown>;
  kill_switch_triggered: boolean;
  status: "ACTIVE" | "MITIGATED" | "INVESTIGATING";
}

/** url_scans tablosu için TypeScript arayüzü */
export interface UrlScan {
  id: string;
  created_at: string;
  url: string;
  risk_score: number;
  verdict: "SAFE" | "SUSPICIOUS" | "MALICIOUS" | "PHISHING" | "ERROR";
  scan_details: Record<string, unknown>;
  triggered_by: string;
}

/** network_devices tablosu için TypeScript arayüzü */
export interface NetworkDevice {
  id: string;
  first_seen: string;
  last_seen: string;
  ip_address: string;
  mac_address: string;
  hostname: string | null;
  vendor: string | null;
  is_suspicious: boolean;
  is_blocked: boolean;
}

// ── Supabase Veritabanı Tipi ───────────────────────────────────────────────

export type Json = string | number | boolean | null | { [key: string]: Json } | Json[];

export interface Database {
  public: {
    Tables: {
      threat_logs: {
        Row: ThreatLog;
        Insert: Omit<ThreatLog, "id" | "created_at">;
        Update: Partial<ThreatLog>;
      };
      url_scans: {
        Row: UrlScan;
        Insert: Omit<UrlScan, "id" | "created_at">;
        Update: Partial<UrlScan>;
      };
      network_devices: {
        Row: NetworkDevice;
        Insert: Partial<Omit<NetworkDevice, "id" | "first_seen">> & {
          ip_address: string;
          mac_address: string;
        };
        Update: Partial<NetworkDevice>;
      };
    };
  };
}

// ── Ortam değişkenleri ─────────────────────────────────────────────────────

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL!;
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY!;

// ── Tarayıcı istemcisi (singleton) ────────────────────────────────────────

let browserClient: SupabaseClient<Database> | null = null;

/**
 * Tarayıcı tarafı Supabase istemcisi.
 * Realtime abonelikleri için kullanın (Client Components).
 */
export function createSupabaseClient(): SupabaseClient<Database> {
  if (browserClient) return browserClient;
  browserClient = createClient<Database>(supabaseUrl, supabaseAnonKey, {
    realtime: { params: { eventsPerSecond: 10 } },
  });
  return browserClient;
}

/**
 * Sunucu tarafı Supabase admin istemcisi (service_role).
 * Yalnızca API Route ve Server Component'lerde kullanın.
 * RLS politikalarını atlar — dışarıya sızdırmayın.
 */
export function createSupabaseAdmin() {
  return createClient<Database>(supabaseUrl, supabaseServiceKey, {
    auth: { persistSession: false },
  });
}
