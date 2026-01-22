import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  /* config options here */
  webpack: (config, { isServer }) => {
    if (isServer) {
      // Handle Prisma client module resolution
      config.resolve = config.resolve || {};
      config.resolve.extensionAlias = {
        '.js': ['.ts', '.js'],
      };
    }
    return config;
  },
};

export default nextConfig;
