/** @type {import('next').NextConfig} */
const nextConfig = {
  experimental: {
    serverComponentsExternalPackages: ['typeorm']
  },
  webpack: (config, { isServer }) => {
    // Exclude Winston from client-side bundle
    if (!isServer) {
      config.resolve.fallback = {
        ...config.resolve.fallback,
        fs: false,
        net: false,
        tls: false,
        crypto: false,
        stream: false,
        url: false,
        zlib: false,
        http: false,
        https: false,
        assert: false,
        os: false,
        path: false,
      };
      
      // Ignore winston and other Node.js specific modules on client side
      config.externals = config.externals || [];
      config.externals.push({
        winston: 'commonjs winston',
      });
    }
    return config;
  },
  async headers() {
    const isProduction = process.env.NODE_ENV === 'production';
    const appUrl = process.env.NEXT_PUBLIC_APP_URL || 'https://docsbox.ro';
    const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',').map(o => o.trim()) || [appUrl];
    
    // Base security headers that apply to all environments
    const baseHeaders = [
      {
        key: 'X-Frame-Options',
        value: 'DENY',
      },
      {
        key: 'X-Content-Type-Options',
        value: 'nosniff',
      },
      {
        key: 'Referrer-Policy',
        value: 'strict-origin-when-cross-origin',
      },
      {
        key: 'Permissions-Policy',
        value: 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), speaker=()',
      },
    ];

    // Production-specific headers
    const productionHeaders = [
      {
        key: 'Strict-Transport-Security',
        value: 'max-age=31536000; includeSubDomains; preload',
      },
      {
        key: 'Content-Security-Policy',
        value: [
          "default-src 'self'",
          "script-src 'self'",
          "style-src 'self'",
          "img-src 'self' data: https:",
          "font-src 'self'",
          "object-src 'none'",
          "base-uri 'self'",
          "form-action 'self'",
          "frame-ancestors 'none'",
          `connect-src 'self' ${allowedOrigins.join(' ')}`,
          "upgrade-insecure-requests"
        ].join('; '),
      },
    ];

    // Development-specific headers (more permissive for HMR)
    const developmentHeaders = [
      {
        key: 'Content-Security-Policy',
        value: [
          "default-src 'self'",
          "script-src 'self' 'unsafe-eval'", // Required for Next.js HMR in dev
          "style-src 'self' 'unsafe-inline'", // Required for styled-components and dev styles
          "img-src 'self' data: https:",
          "font-src 'self'",
          "object-src 'none'",
          "base-uri 'self'",
          "form-action 'self'",
          "frame-ancestors 'none'",
          `connect-src 'self' ${allowedOrigins.join(' ')} ws: wss:`, // Allow WebSocket for HMR
        ].join('; '),
      },
    ];

    return [
      {
        source: '/(.*)',
        headers: [
          ...baseHeaders,
          ...(isProduction ? productionHeaders : developmentHeaders),
        ],
      },
    ];
  },
}

module.exports = nextConfig
