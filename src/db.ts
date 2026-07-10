import { UserRecord } from './types';

/**
 * In-memory store for demo purposes only — swap for Postgres/SQLite + an ORM
 * in a real deployment. Data does not persist across restarts.
 */
const usersById = new Map<string, UserRecord>();
const usersByEmail = new Map<string, string>(); // email -> id

export const users = {
  create(user: UserRecord) {
    usersById.set(user.id, user);
    usersByEmail.set(user.email.toLowerCase(), user.id);
  },
  findByEmail(email: string): UserRecord | undefined {
    const id = usersByEmail.get(email.toLowerCase());
    return id ? usersById.get(id) : undefined;
  },
  findById(id: string): UserRecord | undefined {
    return usersById.get(id);
  },
};

// Revoked access-token IDs (jti). Checked on every authenticated request.
const blocklistedJtis = new Set<string>();

export const blocklist = {
  add(jti: string) {
    blocklistedJtis.add(jti);
  },
  has(jti: string): boolean {
    return blocklistedJtis.has(jti);
  },
};

// Refresh tokens issued per user (jti -> userId), so logout/rotation can revoke them.
const refreshTokens = new Map<string, string>();

export const refreshTokenStore = {
  add(jti: string, userId: string) {
    refreshTokens.set(jti, userId);
  },
  isValid(jti: string, userId: string): boolean {
    return refreshTokens.get(jti) === userId;
  },
  revoke(jti: string) {
    refreshTokens.delete(jti);
  },
};

interface ResetTokenEntry {
  userId: string;
  expiresAt: number;
}

const resetTokens = new Map<string, ResetTokenEntry>();

export const passwordResetStore = {
  create(token: string, userId: string, ttlMs: number) {
    resetTokens.set(token, { userId, expiresAt: Date.now() + ttlMs });
  },
  consume(token: string): string | null {
    const entry = resetTokens.get(token);
    resetTokens.delete(token); // single-use: always remove on lookup
    if (!entry || entry.expiresAt < Date.now()) return null;
    return entry.userId;
  },
};

// WebAuthn challenges issued per user, checked once during registration/login.
const webauthnChallenges = new Map<string, string>();

export const webauthnChallengeStore = {
  set(userId: string, challenge: string) {
    webauthnChallenges.set(userId, challenge);
  },
  take(userId: string): string | undefined {
    const challenge = webauthnChallenges.get(userId);
    webauthnChallenges.delete(userId);
    return challenge;
  },
};
