// backend/src/middleware/rateLimiter.js

/**
 * Creates an in-memory sliding-window rate limiter middleware.
 * Does not require external Redis or external dependencies,
 * and automatically purges expired client windows.
 *
 * @param {object} options
 * @param {number} options.windowMs - Time window in milliseconds (default: 60,000)
 * @param {number} options.max - Maximum requests allowed per window (default: 100)
 * @param {string} options.message - Error message when rate limited
 */
export function createRateLimiter({
  windowMs = 60 * 1000,
  max = 100,
  message = 'Too many requests. Please try again later.',
} = {}) {
  const clients = new Map(); // ip -> Array of timestamps

  // Periodic cleanup of stale entries every 5 minutes
  const cleanupTimer = setInterval(() => {
    const now = Date.now();
    for (const [ip, timestamps] of clients.entries()) {
      const active = timestamps.filter((t) => now - t < windowMs);
      if (active.length === 0) {
        clients.delete(ip);
      } else {
        clients.set(ip, active);
      }
    }
  }, 5 * 60 * 1000);

  // Allow Node process to exit cleanly without waiting on interval
  if (cleanupTimer.unref) {
    cleanupTimer.unref();
  }

  return function rateLimiterMiddleware(req, res, next) {
    const ip =
      (req.headers['x-forwarded-for']?.split(',')[0] || '').trim() ||
      req.ip ||
      req.socket?.remoteAddress ||
      'unknown';

    const now = Date.now();
    const timestamps = clients.get(ip) || [];
    const validTimestamps = timestamps.filter((t) => now - t < windowMs);

    if (validTimestamps.length >= max) {
      const retryAfterSec = Math.ceil((validTimestamps[0] + windowMs - now) / 1000);
      res.setHeader('Retry-After', Math.max(1, retryAfterSec));
      return res.status(429).json({ error: message });
    }

    validTimestamps.push(now);
    clients.set(ip, validTimestamps);
    next();
  };
}

// Global API limiter: generous 300 requests/minute to support SOC dashboard real-time polling
export const apiLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: 300,
  message: 'API rate limit exceeded. Please wait a moment.',
});

// Uploads limiter: 30 uploads/minute
export const uploadLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: 30,
  message: 'Upload rate limit exceeded. Please slow down log uploads.',
});

// AI endpoints limiter: 20 requests/minute to prevent draining upstream LLM quota
export const aiLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: 20,
  message: 'AI investigation rate limit reached. Please wait before generating another report.',
});
