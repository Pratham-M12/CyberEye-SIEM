import { Router } from 'express';

import { runAllRules } from '../rules/engine.js';
import {
  getUploadConfig,
  ingestUploadedFile,
  UploadError,
} from '../uploads/service.js';

const router = Router();

router.get('/config', (req, res) => {
  res.json(getUploadConfig());
});

router.post('/', async (req, res) => {
  try {
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

    console.error('[api] POST /uploads failed:', err);
    res.status(500).json({ error: 'Failed to process upload' });
  }
});

export default router;
