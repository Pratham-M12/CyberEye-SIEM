// backend/src/middleware/auth.js
import { verifyToken } from '../auth/jwt.js';
import { createRateLimiter } from './rateLimiter.js';

/**
 * Dedicated login rate limiter: 10 attempts per 15 minutes per IP.
 * Defends against brute-force attacks and credential stuffing without affecting general API traffic.
 */
export const loginLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many login attempts. Please try again after 15 minutes.',
});

/**
 * Express middleware to verify Bearer JWT in the Authorization header.
 * Attaches verified user payload to req.user: { id, username, role }.
 * Returns HTTP 401 on missing, malformed, expired, or tampered tokens.
 */
export function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || typeof authHeader !== 'string') {
    return res.status(401).json({ error: 'Unauthorized: Missing Authorization header' });
  }

  const parts = authHeader.trim().split(/\s+/);
  if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
    return res.status(401).json({ error: 'Unauthorized: Invalid Authorization header format. Expected "Bearer <token>"' });
  }

  const token = parts[1];
  try {
    const decoded = verifyToken(token);
    if (!decoded || !decoded.id || !decoded.username || !decoded.role) {
      return res.status(401).json({ error: 'Unauthorized: Invalid token claims' });
    }

    req.user = {
      id: decoded.id,
      username: decoded.username,
      role: decoded.role.toLowerCase(),
    };

    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Unauthorized: Token expired' });
    }
    return res.status(401).json({ error: 'Unauthorized: Invalid or tampered token' });
  }
}

/**
 * Role-Based Access Control (RBAC) authorization middleware.
 * Verifies that the authenticated user's role exists in the allowedRoles list.
 * Returns HTTP 403 on role mismatch.
 */
export function requireRole(...allowedRoles) {
  const normalizedAllowed = allowedRoles.flat().map((r) => String(r).toLowerCase());

  return (req, res, next) => {
    if (!req.user || !req.user.role) {
      return res.status(401).json({ error: 'Unauthorized: Authentication required' });
    }

    if (!normalizedAllowed.includes(req.user.role)) {
      return res.status(403).json({
        error: `Forbidden: Access requires one of the following roles: ${normalizedAllowed.join(', ')}`,
      });
    }

    next();
  };
}
