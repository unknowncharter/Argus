/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  images: {
    maximumDiskCacheSize: 500_000_000, // 500MB; prevents unbounded /_next/image cache growth
  },
};

module.exports = nextConfig;
