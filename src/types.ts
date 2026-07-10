import type { AuthenticatorTransportFuture } from '@simplewebauthn/server';

export type Role = 'user' | 'manager' | 'admin';

export interface WebAuthnCredentialRecord {
  credentialId: string; // base64url
  publicKey: string; // base64
  counter: number;
  transports?: AuthenticatorTransportFuture[];
}

export interface UserRecord {
  id: string;
  email: string;
  passwordHash: string;
  role: Role;
  totpSecret: string | null;
  totpEnabled: boolean;
  webauthnCredentials: WebAuthnCredentialRecord[];
}

export interface AccessTokenPayload {
  sub: string; // user id
  role: Role;
  jti: string;
}
