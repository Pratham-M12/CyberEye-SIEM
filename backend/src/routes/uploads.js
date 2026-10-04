import { Router } from 'express';

import { runAllRules } from '../rules/engine.js';
import {
  getUploadConfig,
  ingestUploadedFile,
  UploadError,
} from '../uploads/service.js';
import { uploadLimiter } from '../middleware/rateLimiter.js';
import { authenticate, requireRole } from '../middleware/auth.js';

const router = Router();

// Protect all /api/uploads routes with authentication
router.use(authenticate);

router.get('/config', (req, res) => {
  res.json(getUploadConfig());
});

router.post('/', requireRole('admin', 'analyst'), uploadLimiter, async (req, res) => {
  try {
    if (!req.body || typeof req.body !== 'object') {
      return res.status(400).json({ error: 'Request body must be a valid JSON object' });
    }

    const uploadResult = await ingestUploadedFile(req.body);
    const rulesResult = await runAllRules(req.app.get('io'));

    res.status(201).json({
      ...uploadResult,
      alertsTriggered: rulesResult.totalFired,
    });
  } catch (err) {
    if (err instanceof UploadError) {
      return res.status(err.statusCode).json({ error: err.message });
    }

    console.error('[api] POST /uploads failed:', err.message);
    res.status(500).json({ error: 'Failed to process upload' });
  }
});

export default router;
