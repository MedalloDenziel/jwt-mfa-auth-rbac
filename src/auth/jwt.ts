import jwt from 'jsonwebtoken';
import { v4 as uuid } from 'uuid';
import { config } from '../config';
import { AccessTokenPayload, Role } from '../types';

export function signAccessToken(userId: string, role: Role): string {
  const payload: AccessTokenPayload = { sub: userId, role, jti: uuid() };
  return jwt.sign(payload, config.jwt.accessSecret, { expiresIn: config.jwt.accessTtl });
}

export function verifyAccessToken(token: string): AccessTokenPayload {
  return jwt.verify(token, config.jwt.accessSecret) as AccessTokenPayload;
}

export function signRefreshToken(userId: string): { token: string; jti: string } {
  const jti = uuid();
  const token = jwt.sign({ sub: userId, jti }, config.jwt.refreshSecret, {
    expiresIn: config.jwt.refreshTtl,
  });
  return { token, jti };
}

export function verifyRefreshToken(token: string): { sub: string; jti: string } {
  return jwt.verify(token, config.jwt.refreshSecret) as { sub: string; jti: string };
}

/** Short-lived token proving password step passed, used only to complete an MFA challenge. */
export function signMfaToken(userId: string): string {
  return jwt.sign({ sub: userId }, config.jwt.mfaSecret, { expiresIn: config.jwt.mfaTtl });
}

export function verifyMfaToken(token: string): { sub: string } {
  return jwt.verify(token, config.jwt.mfaSecret) as { sub: string };
}
