import { randomBytes } from 'crypto';
import { passwordResetStore } from '../db';

const RESET_TOKEN_TTL_MS = 30 * 60 * 1000; // 30 minutes

export function createPasswordResetToken(userId: string): string {
  const token = randomBytes(32).toString('hex');
  passwordResetStore.create(token, userId, RESET_TOKEN_TTL_MS);
  return token;
}

/** Returns the associated user id and invalidates the token (single use). */
export function consumePasswordResetToken(token: string): string | null {
  return passwordResetStore.consume(token);
}
