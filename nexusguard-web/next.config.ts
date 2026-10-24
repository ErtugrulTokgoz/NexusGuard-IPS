/**
 * @file next.config.ts
 * @description NexusGuard IPS — Next.js Yapılandırması
 *
 * PWA desteği @ducanh2912/next-pwa ile sağlanmıştır.
 * Not: @ducanh2912/next-pwa Webpack tabanlı olduğundan `next dev --webpack`
 * ve `next build --webpack` modunda çalışır.
 */

import type { NextConfig } from "next";
import withPWA from "@ducanh2912/next-pwa";

const pwaConfig = withPWA({
  dest: "public",
  cacheOnFrontEndNav: true,
  aggressiveFrontEndNavCaching: true,
  reloadOnOnline: true,
  disable: process.env.NODE_ENV === "development",
  workboxOptions: {
    disableDevLogs: true,
    runtimeCaching: [
      {
        urlPattern: /^\/api\/.*/i,
        handler: "NetworkFirst",
        options: {
          cacheName: "nexusguard-api-cache",
          networkTimeoutSeconds: 10,
        },
      },
    ],
  },
});

const nextConfig: NextConfig = {
  cacheComponents: true,
  partialPrefetching: true,
};

export default pwaConfig(nextConfig);
