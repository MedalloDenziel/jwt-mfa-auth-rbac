import { Router } from 'express';
import { v4 as uuid } from 'uuid';
import { users, blocklist, refreshTokenStore, webauthnChallengeStore } from '../db';
import { hashPassword, verifyPassword } from '../auth/password';
import {
  signAccessToken,
  signRefreshToken,
  verifyRefreshToken,
  signMfaToken,
  verifyMfaToken,
} from '../auth/jwt';
import { generateTotpSecret, buildTotpQrCode, verifyTotpCode } from '../auth/totp';
import { createPasswordResetToken, consumePasswordResetToken } from '../auth/password-reset';
import {
  buildRegistrationOptions,
  verifyRegistration,
  buildAuthenticationOptions,
  verifyAuthentication,
} from '../auth/webauthn';
import { requireAuth } from '../auth/rbac.middleware';
import { Role, UserRecord } from '../types';

export const authRouter = Router();

function issueTokenPair(user: UserRecord) {
  const accessToken = signAccessToken(user.id, user.role);
  const { token: refreshToken, jti } = signRefreshToken(user.id);
  refreshTokenStore.add(jti, user.id);
  return { accessToken, refreshToken };
}

authRouter.post('/register', async (req, res) => {
  const { email, password, role } = req.body as { email?: string; password?: string; role?: Role };
  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required' });
  }
  if (users.findByEmail(email)) {
    return res.status(409).json({ error: 'A user with that email already exists' });
  }

  const user: UserRecord = {
    id: uuid(),
    email,
    passwordHash: await hashPassword(password),
    role: role ?? 'user',
    totpSecret: null,
    totpEnabled: false,
    webauthnCredentials: [],
  };
  users.create(user);

  return res.status(201).json({ id: user.id, email: user.email, role: user.role });
});

authRouter.post('/login', async (req, res) => {
  const { email, password } = req.body as { email?: string; password?: string };
  const user = email ? users.findByEmail(email) : undefined;

  if (!user || !password || !(await verifyPassword(password, user.passwordHash))) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  if (user.totpEnabled || user.webauthnCredentials.length > 0) {
    return res.status(200).json({ mfaRequired: true, mfaToken: signMfaToken(user.id) });
  }

  return res.status(200).json(issueTokenPair(user));
});

authRouter.post('/mfa/totp/setup', requireAuth, async (req, res) => {
  const user = users.findById(req.user!.id)!;
  const secret = generateTotpSecret();
  user.totpSecret = secret; // not enabled until confirmed via /mfa/totp/enable
  const qrCode = await buildTotpQrCode(user.email, secret, 'jwt-mfa-auth-rbac demo');
  return res.status(200).json({ secret, qrCode });
});

authRouter.post('/mfa/totp/enable', requireAuth, (req, res) => {
  const user = users.findById(req.user!.id)!;
  const { code } = req.body as { code?: string };
  if (!user.totpSecret || !code || !verifyTotpCode(user.totpSecret, code)) {
    return res.status(400).json({ error: 'Invalid TOTP code' });
  }
  user.totpEnabled = true;
  return res.status(200).json({ totpEnabled: true });
});

authRouter.post('/mfa/totp/verify', (req, res) => {
  const { mfaToken, code } = req.body as { mfaToken?: string; code?: string };
  if (!mfaToken || !code) return res.status(400).json({ error: 'mfaToken and code are required' });

  let userId: string;
  try {
    userId = verifyMfaToken(mfaToken).sub;
  } catch {
    return res.status(401).json({ error: 'Invalid or expired mfaToken' });
  }

  const user = users.findById(userId);
  if (!user?.totpSecret || !verifyTotpCode(user.totpSecret, code)) {
    return res.status(401).json({ error: 'Invalid TOTP code' });
  }

  return res.status(200).json(issueTokenPair(user));
});

authRouter.post('/webauthn/register/options', requireAuth, async (req, res) => {
  const user = users.findById(req.user!.id)!;
  const options = await buildRegistrationOptions(user);
  webauthnChallengeStore.set(user.id, options.challenge);
  return res.status(200).json(options);
});

authRouter.post('/webauthn/register/verify', requireAuth, async (req, res) => {
  const user = users.findById(req.user!.id)!;
  const expectedChallenge = webauthnChallengeStore.take(user.id);
  if (!expectedChallenge) return res.status(400).json({ error: 'No pending registration challenge' });

  try {
    const credential = await verifyRegistration(req.body, expectedChallenge);
    user.webauthnCredentials.push(credential);
    return res.status(200).json({ verified: true });
  } catch (err) {
    return res.status(400).json({ error: (err as Error).message });
  }
});

authRouter.post('/webauthn/login/options', async (req, res) => {
  const { email } = req.body as { email?: string };
  const user = email ? users.findByEmail(email) : undefined;
  if (!user || user.webauthnCredentials.length === 0) {
    return res.status(400).json({ error: 'No passkeys registered for this account' });
  }

  const options = await buildAuthenticationOptions(user);
  webauthnChallengeStore.set(user.id, options.challenge);
  return res.status(200).json(options);
});

authRouter.post('/webauthn/login/verify', async (req, res) => {
  const { email, response } = req.body as { email?: string; response?: any };
  const user = email ? users.findByEmail(email) : undefined;
  const expectedChallenge = user ? webauthnChallengeStore.take(user.id) : undefined;
  if (!user || !expectedChallenge) {
    return res.status(400).json({ error: 'No pending authentication challenge' });
  }

  const credential = user.webauthnCredentials.find((c) => c.credentialId === response?.id);
  if (!credential) return res.status(400).json({ error: 'Unknown credential' });

  try {
    credential.counter = await verifyAuthentication(response, expectedChallenge, credential);
    return res.status(200).json(issueTokenPair(user));
  } catch (err) {
    return res.status(400).json({ error: (err as Error).message });
  }
});

authRouter.post('/refresh', (req, res) => {
  const { refreshToken } = req.body as { refreshToken?: string };
  if (!refreshToken) return res.status(400).json({ error: 'refreshToken is required' });

  try {
    const { sub, jti } = verifyRefreshToken(refreshToken);
    if (!refreshTokenStore.isValid(jti, sub)) {
      return res.status(401).json({ error: 'Refresh token has been revoked' });
    }
    const user = users.findById(sub);
    if (!user) return res.status(401).json({ error: 'User no longer exists' });

    refreshTokenStore.revoke(jti); // rotate: old refresh token is single-use
    return res.status(200).json(issueTokenPair(user));
  } catch {
    return res.status(401).json({ error: 'Invalid or expired refresh token' });
  }
});

authRouter.post('/logout', requireAuth, (req, res) => {
  blocklist.add(req.user!.jti);
  return res.status(200).json({ loggedOut: true });
});

authRouter.post('/password-reset/request', (req, res) => {
  const { email } = req.body as { email?: string };
  const user = email ? users.findByEmail(email) : undefined;

  // Always return 200 so the endpoint doesn't reveal which emails are registered.
  if (!user) return res.status(200).json({ requested: true });

  const token = createPasswordResetToken(user.id);
  // In production this token is emailed to the user, never returned in the response.
  return res.status(200).json({ requested: true, devOnlyResetToken: token });
});

authRouter.post('/password-reset/confirm', async (req, res) => {
  const { token, newPassword } = req.body as { token?: string; newPassword?: string };
  if (!token || !newPassword) {
    return res.status(400).json({ error: 'token and newPassword are required' });
  }

  const userId = consumePasswordResetToken(token);
  const user = userId ? users.findById(userId) : undefined;
  if (!user) return res.status(400).json({ error: 'Invalid or expired reset token' });

  user.passwordHash = await hashPassword(newPassword);
  return res.status(200).json({ reset: true });
});
