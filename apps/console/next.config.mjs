/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // The console imports the ESM library from the monorepo; let Next transpile it.
  transpilePackages: ["@countersignlabs/counter-sign"],
};

export default nextConfig;
