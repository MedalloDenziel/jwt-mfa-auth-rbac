# jwt-mfa-auth-rbac

A standalone JWT authentication system with role-based access control, multi-factor
authentication (TOTP + WebAuthn passkeys), revocable tokens, and a single-use
password-reset flow.

## Overview

Most auth tutorials stop at "sign a JWT and check it." This project goes further: it
demonstrates a production-shaped auth system with role-based permissions (e.g. user /
manager / admin), a token blocklist for immediate revocation (logout, password change,
suspicious activity), and two MFA methods side by side — TOTP for app-based codes and
WebAuthn for passkeys. This is a generic rebuild of an auth pattern used in a real
production system, with no proprietary code, data, or business logic included.

## Features

- JWT access + refresh token issuance and verification
- Role-based access control middleware (route-level and resource-level checks)
- TOTP-based MFA (compatible with Google Authenticator / Authy)
- WebAuthn passkey registration and login
- Revocable tokens via a blocklist table (instant logout / forced re-auth)
- Single-use, time-limited password-reset tokens

## Tech Stack

- Node.js / TypeScript
- JWT (jsonwebtoken)
- WebAuthn (`@simplewebauthn/server`)
- TOTP (`otplib`)
- [Database/ORM used, e.g. Prisma + SQLite or Postgres]

## Architecture

```
Client
  │
  ├─ POST /auth/login ──────────────► verify credentials ─► issue access + refresh JWT
  ├─ POST /auth/mfa/totp/verify ────► verify TOTP code ────► elevate session
  ├─ POST /auth/mfa/webauthn/verify ► verify passkey assertion ─► elevate session
  ├─ POST /auth/logout ─────────────► add token jti to blocklist table
  └─ POST /auth/password-reset ─────► issue single-use reset token ─► email link
```

Every protected route checks: (1) JWT signature/expiry, (2) blocklist membership,
(3) role permission for the requested resource.

## Screenshots / Demo

![screenshot](./docs/screenshot.png) - (to be added)

## Getting Started

### Prerequisites

- Node.js 20+
- A `.env` file (see `.env.example`) with `JWT_SECRET`, database connection string, etc.

### Installation

```bash
git clone https://github.com/MedalloDenziel/jwt-mfa-auth-rbac.git
cd jwt-mfa-auth-rbac
npm install
```

### Running locally

```bash
cp .env.example .env
npm run dev
```

## Project Structure

```
src/
├── auth/
│   ├── jwt.ts            # sign/verify access + refresh tokens
│   ├── blocklist.ts       # revocation checks
│   ├── rbac.middleware.ts # role/permission guards
│   ├── totp.ts            # TOTP setup + verification
│   └── webauthn.ts         # passkey registration + assertion
├── routes/
└── db/
```

## Notes

Given more time, I'd add device-bound refresh token rotation and rate limiting on the
MFA verification endpoints to reduce brute-force risk.

## License

MIT
