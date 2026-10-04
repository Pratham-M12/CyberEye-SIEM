// backend/src/auth/jwt.js
import jwt from 'jsonwebtoken';
import 'dotenv/config';

const FALLBACK_DEV_SECRET = 'cybereye-siem-default-development-secret-key-32chars-min';
const JWT_SECRET = process.env.JWT_SECRET || FALLBACK_DEV_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '8h';

/**
 * Generates a signed JWT containing minimal user identity claims.
 * Contains only { id, username, role }.
 */
export function signToken(user) {
  if (!user || !user.id || !user.username || !user.role) {
    throw new Error('User identity (id, username, role) is required to sign JWT');
  }

  return jwt.sign(
    {
      id: user.id,
      username: user.username,
      role: user.role,
    },
    JWT_SECRET,
    {
      expiresIn: JWT_EXPIRES_IN,
      algorithm: 'HS256',
    }
  );
}

/**
 * Verifies a JWT token signature and expiration.
 * Returns decoded payload if valid, or null on any failure.
 */
export function verifyToken(token) {
  if (!token || typeof token !== 'string') {
    return null;
  }

  try {
    return jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
  } catch (err) {
    return null;
  }
}
