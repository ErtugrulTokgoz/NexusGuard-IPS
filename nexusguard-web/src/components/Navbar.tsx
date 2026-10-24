/**
 * @file src/components/Navbar.tsx
 * @description NexusGuard IPS — Üst Navigasyon Çubuğu
 *
 * Sabit konumlu (sticky) kurumsal navbar.
 * Aktif sayfa linki otomatik olarak vurgulanır (usePathname).
 */

"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ShieldCheckIcon, Bars3Icon } from "@heroicons/react/24/outline";
import { useState } from "react";

const NAV_LINKS = [
  { href: "/", label: "Dashboard" },
  { href: "/topology", label: "Ağ Topolojisi" },
  { href: "/logs", label: "Güvenlik Logları" },
];

export default function Navbar() {
  const pathname = usePathname();
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <nav className="fixed top-0 left-0 right-0 z-50 bg-gray-900/95 backdrop-blur-sm border-b border-gray-800">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">

          {/* ── Logo ── */}
          <Link href="/" className="flex items-center gap-2 group">
            <ShieldCheckIcon
              style={{ width: "28px", height: "28px", minWidth: "28px", minHeight: "28px" }}
              className="w-7 h-7 text-cyan-400 group-hover:text-cyan-300 transition-colors flex-shrink-0"
            />
            <span className="font-bold text-lg tracking-tight">
              <span className="text-cyan-400">Nexus</span>
              <span className="text-white">Guard</span>
              <span className="ml-2 text-xs font-mono text-gray-500 bg-gray-800 px-1.5 py-0.5 rounded">
                IPS
              </span>
            </span>
          </Link>

          {/* ── Desktop Navigasyon ── */}
          <div className="hidden md:flex items-center gap-1">
            {NAV_LINKS.map(({ href, label }) => {
              const isActive = pathname === href;
              return (
                <Link
                  key={href}
                  href={href}
                  className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                    isActive
                      ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/20"
                      : "text-gray-400 hover:text-white hover:bg-gray-800"
                  }`}
                >
                  {label}
                </Link>
              );
            })}
          </div>

          {/* ── Canlı Durum Göstergesi ── */}
          <div className="hidden md:flex items-center gap-2 text-xs text-gray-500">
            <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
            <span>Sistem Aktif</span>
          </div>

          {/* ── Mobil Menü Butonu ── */}
          <button
            className="md:hidden p-2 rounded-lg text-gray-400 hover:text-white hover:bg-gray-800"
            onClick={() => setMobileOpen(!mobileOpen)}
            aria-label="Menüyü aç/kapat"
          >
            <Bars3Icon className="w-5 h-5" />
          </button>
        </div>

        {/* ── Mobil Menü ── */}
        {mobileOpen && (
          <div className="md:hidden py-2 border-t border-gray-800">
            {NAV_LINKS.map(({ href, label }) => (
              <Link
                key={href}
                href={href}
                className="block px-4 py-2 text-sm text-gray-400 hover:text-white hover:bg-gray-800 rounded-lg"
                onClick={() => setMobileOpen(false)}
              >
                {label}
              </Link>
            ))}
          </div>
        )}
      </div>
    </nav>
  );
}
