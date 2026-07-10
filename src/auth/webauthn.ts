import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import type {
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
} from '@simplewebauthn/server';
import { config } from '../config';
import { UserRecord, WebAuthnCredentialRecord } from '../types';

const { rpId, rpName, origin } = config.webauthn;

export function buildRegistrationOptions(user: UserRecord) {
  return generateRegistrationOptions({
    rpID: rpId,
    rpName,
    userID: Buffer.from(user.id),
    userName: user.email,
    attestationType: 'none',
    excludeCredentials: user.webauthnCredentials.map((cred) => ({
      id: cred.credentialId,
      transports: cred.transports,
    })),
  });
}

export async function verifyRegistration(
  response: RegistrationResponseJSON,
  expectedChallenge: string,
): Promise<WebAuthnCredentialRecord> {
  const verification = await verifyRegistrationResponse({
    response,
    expectedChallenge,
    expectedOrigin: origin,
    expectedRPID: rpId,
  });

  if (!verification.verified || !verification.registrationInfo) {
    throw new Error('WebAuthn registration verification failed');
  }

  const { credential } = verification.registrationInfo;
  return {
    credentialId: credential.id,
    publicKey: Buffer.from(credential.publicKey).toString('base64'),
    counter: credential.counter,
    transports: credential.transports,
  };
}

export function buildAuthenticationOptions(user: UserRecord) {
  return generateAuthenticationOptions({
    rpID: rpId,
    allowCredentials: user.webauthnCredentials.map((cred) => ({
      id: cred.credentialId,
      transports: cred.transports,
    })),
  });
}

export async function verifyAuthentication(
  response: AuthenticationResponseJSON,
  expectedChallenge: string,
  credential: WebAuthnCredentialRecord,
): Promise<number> {
  const verification = await verifyAuthenticationResponse({
    response,
    expectedChallenge,
    expectedOrigin: origin,
    expectedRPID: rpId,
    credential: {
      id: credential.credentialId,
      publicKey: Buffer.from(credential.publicKey, 'base64'),
      counter: credential.counter,
      transports: credential.transports,
    },
  });

  if (!verification.verified) {
    throw new Error('WebAuthn authentication verification failed');
  }

  return verification.authenticationInfo.newCounter;
}
