/** @type {import('next').NextConfig} */
const nextConfig = {
  // The @proteles/* packages ship pre-built ESM in `dist/`, so no transpilation
  // is needed. (If you consume them from source in a monorepo, add them to
  // `transpilePackages` instead.)
};

export default nextConfig;
