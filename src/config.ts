import 'dotenv/config';
import type { SignOptions } from 'jsonwebtoken';

type Ttl = SignOptions['expiresIn'];

function required(name: string, fallback?: string): string {
  const value = process.env[name] ?? fallback;
  if (!value) throw new Error(`Missing required env var: ${name}`);
  return value;
}

export const config = {
  port: Number(process.env.PORT ?? 3000),
  jwt: {
    accessSecret: required('JWT_ACCESS_SECRET'),
    refreshSecret: required('JWT_REFRESH_SECRET'),
    mfaSecret: required('MFA_TOKEN_SECRET'),
    accessTtl: (process.env.ACCESS_TOKEN_TTL ?? '15m') as Ttl,
    refreshTtl: (process.env.REFRESH_TOKEN_TTL ?? '7d') as Ttl,
    mfaTtl: (process.env.MFA_TOKEN_TTL ?? '5m') as Ttl,
  },
  webauthn: {
    rpId: process.env.RP_ID ?? 'localhost',
    rpName: process.env.RP_NAME ?? 'jwt-mfa-auth-rbac demo',
    origin: process.env.ORIGIN ?? 'http://localhost:3000',
  },
};
