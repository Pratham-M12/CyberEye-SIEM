// backend/src/services/userService.js
import { esClient, USERS_INDEX } from '../es/client.js';
import { hashPassword } from '../auth/passwords.js';

export const VALID_ROLES = Object.freeze(['admin', 'analyst', 'read_only']);

/**
 * Strips sensitive password credentials from a user record before returning to clients.
 */
export function sanitizeUser(user) {
  if (!user) return null;
  const { passwordHash, salt, ...safe } = user;
  return safe;
}

/**
 * Normalizes username for consistent lookups and prevents casing confusion.
 */
export function normalizeUsername(username) {
  if (typeof username !== 'string') return '';
  return username.trim().toLowerCase();
}

/**
 * Retrieves a user record by username from Elasticsearch.
 */
export async function getUserByUsername(username, includeCredentials = false) {
  const normalized = normalizeUsername(username);
  if (!normalized) return null;

  try {
    const doc = await esClient.get({
      index: USERS_INDEX,
      id: normalized,
    });
    const user = { id: doc._id, ...doc._source };
    return includeCredentials ? user : sanitizeUser(user);
  } catch (err) {
    if (err.meta?.statusCode === 404) return null;
    throw err;
  }
}

/**
 * Retrieves a user record by document ID (which is the normalized username).
 */
export async function getUserById(id, includeCredentials = false) {
  return getUserByUsername(id, includeCredentials);
}

/**
 * Creates a new user record in Elasticsearch using atomic create semantics.
 */
export async function createUser({ username, password, role = 'analyst' }) {
  const normalized = normalizeUsername(username);
  if (!normalized || normalized.length < 3 || normalized.length > 50) {
    const err = new Error('Username must be between 3 and 50 characters');
    err.statusCode = 400;
    throw err;
  }

  if (!/^[a-zA-Z0-9._-]+$/.test(normalized)) {
    const err = new Error('Username can only contain alphanumeric characters, dots, dashes, and underscores');
    err.statusCode = 400;
    throw err;
  }

  const normalizedRole = String(role).toLowerCase();
  if (!VALID_ROLES.includes(normalizedRole)) {
    const err = new Error(`Invalid role: ${role}. Allowed roles: ${VALID_ROLES.join(', ')}`);
    err.statusCode = 400;
    throw err;
  }

  const { passwordHash, salt } = await hashPassword(password);
  const now = new Date().toISOString();

  const userDoc = {
    username: normalized,
    passwordHash,
    salt,
    role: normalizedRole,
    createdAt: now,
    updatedAt: now,
    isActive: true,
    lastLoginAt: null,
  };

  try {
    await esClient.create({
      index: USERS_INDEX,
      id: normalized,
      document: userDoc,
      refresh: 'wait_for',
    });

    return sanitizeUser({ id: normalized, ...userDoc });
  } catch (err) {
    if (err.meta?.statusCode === 409) {
      const conflictErr = new Error('Username already exists');
      conflictErr.statusCode = 409;
      throw conflictErr;
    }
    throw err;
  }
}

/**
 * Updates user attributes (role, active status, or password).
 * Includes guard to prevent deactivating the last active administrator.
 */
export async function updateUser(id, { role, password, isActive }) {
  const existing = await getUserById(id, true);
  if (!existing) {
    const notFoundErr = new Error('User not found');
    notFoundErr.statusCode = 404;
    throw notFoundErr;
  }

  if (
    (isActive === false || (role && role !== 'admin')) &&
    existing.role === 'admin' &&
    existing.isActive
  ) {
    const adminCount = await countActiveAdmins();
    if (adminCount <= 1) {
      const lastAdminErr = new Error('Cannot modify or deactivate the last active administrator');
      lastAdminErr.statusCode = 400;
      throw lastAdminErr;
    }
  }

  const updates = {
    updatedAt: new Date().toISOString(),
  };

  if (role !== undefined) {
    const normalizedRole = String(role).toLowerCase();
    if (!VALID_ROLES.includes(normalizedRole)) {
      const err = new Error(`Invalid role: ${role}. Allowed roles: ${VALID_ROLES.join(', ')}`);
      err.statusCode = 400;
      throw err;
    }
    updates.role = normalizedRole;
  }

  if (isActive !== undefined) {
    updates.isActive = Boolean(isActive);
  }

  if (password) {
    const { passwordHash, salt } = await hashPassword(password);
    updates.passwordHash = passwordHash;
    updates.salt = salt;
  }

  await esClient.update({
    index: USERS_INDEX,
    id: existing.id,
    doc: updates,
    refresh: 'wait_for',
  });

  return sanitizeUser({ ...existing, ...updates });
}

/**
 * Updates lastLoginAt timestamp.
 */
export async function updateLastLogin(id) {
  try {
    await esClient.update({
      index: USERS_INDEX,
      id,
      doc: { lastLoginAt: new Date().toISOString() },
    });
  } catch (err) {
    // Non-critical background update
  }
}

/**
 * Lists all users with credential fields excluded.
 */
export async function listUsers() {
  const result = await esClient.search({
    index: USERS_INDEX,
    size: 200,
    sort: [{ createdAt: 'asc' }],
    _source: { excludes: ['passwordHash', 'salt'] },
    query: { match_all: {} },
  });

  return result.hits.hits.map((h) => ({ id: h._id, ...h._source }));
}

/**
 * Deletes a user account with last-active-admin protection.
 */
export async function deleteUser(id) {
  const existing = await getUserById(id, true);
  if (!existing) {
    const notFoundErr = new Error('User not found');
    notFoundErr.statusCode = 404;
    throw notFoundErr;
  }

  if (existing.role === 'admin' && existing.isActive) {
    const adminCount = await countActiveAdmins();
    if (adminCount <= 1) {
      const lastAdminErr = new Error('Cannot delete the last active administrator');
      lastAdminErr.statusCode = 400;
      throw lastAdminErr;
    }
  }

  await esClient.delete({
    index: USERS_INDEX,
    id,
    refresh: 'wait_for',
  });

  return { success: true };
}

/**
 * Counts currently active administrators.
 */
export async function countActiveAdmins() {
  const result = await esClient.count({
    index: USERS_INDEX,
    query: {
      bool: {
        filter: [
          { term: { role: 'admin' } },
          { term: { isActive: true } },
        ],
      },
    },
  });
  return result.count;
}
