import { Router } from 'express';
import { requireAuth, requireRole } from '../auth/rbac.middleware';

export const adminRouter = Router();

// Example protected resource demonstrating the RBAC middleware in action.
adminRouter.get('/ping', requireAuth, requireRole('admin'), (req, res) => {
  res.status(200).json({ pong: true, userId: req.user!.id });
});
