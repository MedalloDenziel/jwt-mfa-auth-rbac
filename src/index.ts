import express from 'express';
import { config } from './config';
import { authRouter } from './routes/auth.routes';
import { adminRouter } from './routes/admin.routes';

const app = express();
app.use(express.json());

app.use('/auth', authRouter);
app.use('/admin', adminRouter);

app.get('/health', (_req, res) => res.status(200).json({ ok: true }));

app.listen(config.port, () => {
  console.log(`jwt-mfa-auth-rbac demo listening on http://localhost:${config.port}`);
});
