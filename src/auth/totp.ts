import { authenticator } from 'otplib';
import QRCode from 'qrcode';

export function generateTotpSecret(): string {
  return authenticator.generateSecret();
}

export function buildTotpQrCode(email: string, secret: string, issuer: string): Promise<string> {
  const otpauthUrl = authenticator.keyuri(email, issuer, secret);
  return QRCode.toDataURL(otpauthUrl);
}

export function verifyTotpCode(secret: string, code: string): boolean {
  return authenticator.check(code, secret);
}
