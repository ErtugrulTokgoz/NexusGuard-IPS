/**
 * @file src/app/layout.tsx
 * @description NexusGuard IPS — Kök Layout
 *
 * Tüm sayfaların paylaştığı temel HTML yapısı.
 * Koyu mod (dark), kurumsal Geist font ve Navbar burada tanımlanır.
 */

import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import Navbar from "@/components/Navbar";

const geist = Geist({ subsets: ["latin"], variable: "--font-geist" });
const geistMono = Geist_Mono({
  subsets: ["latin"],
  variable: "--font-geist-mono",
});

export const metadata: Metadata = {
  title: "NexusGuard IPS | TÜBİTAK 2209-A",
  description: "Gerçek zamanlı ağ izleme ve saldırı önleme sistemi",
  keywords: ["IPS", "network security", "ARP spoofing", "cybersecurity"],
  manifest: "/manifest.json",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="tr" className="dark">
      <body
        className={`${geist.variable} ${geistMono.variable} bg-gray-950 text-gray-100 min-h-screen antialiased`}
      >
        {/* Üst navigasyon çubuğu — tüm sayfalarda sabit */}
        <Navbar />

        {/* Sayfa içeriği — navbar yüksekliği kadar (pt-16) aşağıda başlar */}
        <main className="pt-16">{children}</main>
      </body>
    </html>
  );
}
