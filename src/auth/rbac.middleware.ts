import { NextFunction, Request, Response } from 'express';
import { verifyAccessToken } from './jwt';
import { blocklist } from '../db';
import { Role } from '../types';

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      user?: { id: string; role: Role; jti: string };
    }
  }
}

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing bearer token' });
  }

  try {
    const payload = verifyAccessToken(header.slice('Bearer '.length));
    if (blocklist.has(payload.jti)) {
      return res.status(401).json({ error: 'Token has been revoked' });
    }
    req.user = { id: payload.sub, role: payload.role, jti: payload.jti };
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

export function requireRole(...roles: Role[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}
