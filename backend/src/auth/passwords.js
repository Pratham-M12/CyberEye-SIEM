// backend/src/auth/passwords.js
import { scrypt, randomBytes, timingSafeEqual } from 'crypto';
import { promisify } from 'util';

const scryptAsync = promisify(scrypt);

const KEY_LENGTH = 64;
const SCRYPT_OPTIONS = {
  N: 16384,
  r: 8,
  p: 1,
  maxmem: 32 * 1024 * 1024,
};

/**
 * Hashes a plaintext password using crypto.scrypt with a random 16-byte salt.
 * Returns { passwordHash, salt }.
 */
export async function hashPassword(password) {
  if (typeof password !== 'string' || password.length < 8) {
    throw new Error('Password must be at least 8 characters long');
  }
  const salt = randomBytes(16).toString('hex');
  const derivedKey = await scryptAsync(password, salt, KEY_LENGTH, SCRYPT_OPTIONS);
  return {
    passwordHash: derivedKey.toString('hex'),
    salt,
  };
}

/**
 * Verifies a plaintext password against the stored passwordHash and salt
 * using timingSafeEqual to prevent side-channel timing leaks.
 */
export async function verifyPassword(password, storedHash, salt) {
  if (typeof password !== 'string' || !storedHash || !salt) {
    return false;
  }
  try {
    const derivedKey = await scryptAsync(password, salt, KEY_LENGTH, SCRYPT_OPTIONS);
    const keyBuffer = Buffer.from(derivedKey.toString('hex'), 'hex');
    const storedBuffer = Buffer.from(storedHash, 'hex');

    if (keyBuffer.length !== storedBuffer.length) {
      return false;
    }

    return timingSafeEqual(keyBuffer, storedBuffer);
  } catch (err) {
    return false;
  }
}
