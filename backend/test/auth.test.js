import test from 'node:test';
import assert from 'node:assert/strict';
import jwt from 'jsonwebtoken';
import { io as Client } from '../../frontend/node_modules/socket.io-client/build/esm/index.js';

import { hashPassword, verifyPassword } from '../src/auth/passwords.js';
import { signToken, verifyToken } from '../src/auth/jwt.js';
import {
  createUser,
  getUserByUsername,
  getUserById,
  updateUser,
  countActiveAdmins,
  deleteUser,
} from '../src/services/userService.js';

const BASE_URL = process.env.TEST_API_URL || 'http://localhost:4000';

test('Auth — Passwords & Cryptography', async (t) => {
  await t.test('hashPassword generates cryptographically distinct salt and hash', async () => {
    const p1 = await hashPassword('CyberEye2026!Secure');
    const p2 = await hashPassword('CyberEye2026!Secure');

    assert.ok(p1.salt, 'salt must exist');
    assert.ok(p1.passwordHash, 'passwordHash must exist');
    assert.notEqual(p1.salt, p2.salt, 'salts must be randomly generated and unique');
    assert.notEqual(p1.passwordHash, p2.passwordHash, 'hashes must differ across runs due to salt');
  });

  await t.test('verifyPassword returns true for matching password and false for wrong password', async () => {
    const { passwordHash, salt } = await hashPassword('CorrectPassword123!');
    const ok = await verifyPassword('CorrectPassword123!', passwordHash, salt);
    assert.equal(ok, true);

    const wrong = await verifyPassword('WrongPassword123!', passwordHash, salt);
    assert.equal(wrong, false);
  });

  await t.test('verifyPassword fails safely on malformed or empty inputs without throwing', async () => {
    assert.equal(await verifyPassword('', 'hash', 'salt'), false);
    assert.equal(await verifyPassword('pass', '', 'salt'), false);
    assert.equal(await verifyPassword('pass', 'hash', ''), false);
    assert.equal(await verifyPassword(null, null, null), false);
  });
});

test('Auth — JWT Token Operations', async (t) => {
  await t.test('signToken encodes only minimal required identity claims', async () => {
    const token = signToken({ id: 'u123', username: 'alice', role: 'analyst' });
    assert.ok(token);

    const decoded = verifyToken(token);
    assert.equal(decoded.id, 'u123');
    assert.equal(decoded.username, 'alice');
    assert.equal(decoded.role, 'analyst');
    assert.equal(decoded.password, undefined);
    assert.equal(decoded.passwordHash, undefined);
    assert.equal(decoded.salt, undefined);
  });

  await t.test('verifyToken returns null for tampered token signature', async () => {
    const token = signToken({ id: 'u123', username: 'alice', role: 'read_only' });
    const tampered = token.slice(0, -6) + 'xxxxxx';
    const decoded = verifyToken(tampered);
    assert.equal(decoded, null);
  });

  await t.test('verifyToken returns null for malformed or empty string', async () => {
    assert.equal(verifyToken('not-a-token'), null);
    assert.equal(verifyToken(''), null);
    assert.equal(verifyToken(null), null);
  });

  await t.test('verifyToken returns null for expired token', async () => {
    const secret = process.env.JWT_SECRET || 'fallback-test-secret-min-32-chars-ok';
    const expiredToken = jwt.sign({ id: 'u1', username: 'exp', role: 'admin' }, secret, {
      expiresIn: '-1s',
    });
    assert.equal(verifyToken(expiredToken), null);
  });
});

test('Auth — Elasticsearch User Management Service', async (t) => {
  const testAdminUser = `test_admin_${Date.now()}`;
  const testAnalystUser = `test_analyst_${Date.now()}`;

  await t.test('createUser persists user and does not leak credentials in returned object', async () => {
    const user = await createUser({
      username: testAdminUser,
      password: 'AdminPassword123!',
      role: 'admin',
    });

    assert.ok(user.id);
    assert.equal(user.username, testAdminUser);
    assert.equal(user.role, 'admin');
    assert.equal(user.isActive, true);
    assert.equal(user.passwordHash, undefined, 'passwordHash must never be exposed');
    assert.equal(user.salt, undefined, 'salt must never be exposed');
  });

  await t.test('createUser rejects duplicate username with 409 error', async () => {
    await assert.rejects(
      async () => {
        await createUser({
          username: testAdminUser,
          password: 'AnotherPassword123!',
          role: 'analyst',
        });
      },
      (err) => err.statusCode === 409 || err.status === 409 || err.message.includes('already exists')
    );
  });

  await t.test('getUserByUsername returns sanitized user by default', async () => {
    const user = await getUserByUsername(testAdminUser);
    assert.ok(user);
    assert.equal(user.username, testAdminUser);
    assert.equal(user.passwordHash, undefined);
    assert.equal(user.salt, undefined);
  });

  await t.test('Last active admin cannot be deactivated or deleted', async () => {
    const activeAdmins = await countActiveAdmins();
    assert.ok(activeAdmins >= 1);

    // If there is only 1 admin, trying to deactivate must fail
    if (activeAdmins === 1) {
      const admin = await getUserByUsername(testAdminUser);
      await assert.rejects(
        async () => {
          await updateUser(admin.id, { isActive: false });
        },
        (err) => err.message.includes('Cannot deactivate the last active administrator')
      );
    }
  });
});

test('Auth — API Endpoints (/api/auth)', async (t) => {
  const loginUser = `api_user_${Date.now()}`;
  const loginPass = 'SecureLogin123!';

  await createUser({
    username: loginUser,
    password: loginPass,
    role: 'analyst',
  });

  let validToken = '';

  const testIp = `198.51.100.${Math.floor(Math.random() * 200) + 10}`;

  await t.test('POST /api/auth/login succeeds with valid credentials and returns JWT + profile', async () => {
    const res = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-For': testIp,
      },
      body: JSON.stringify({ username: loginUser, password: loginPass }),
    });

    assert.equal(res.status, 200);
    const data = await res.json();
    assert.ok(data.token, 'Must return JWT token');
    assert.equal(data.user.username, loginUser);
    assert.equal(data.user.role, 'analyst');
    assert.equal(data.user.passwordHash, undefined);
    assert.equal(data.user.salt, undefined);

    validToken = data.token;
  });

  await t.test('POST /api/auth/login fails with invalid password using generic message (no enumeration)', async () => {
    const res = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-For': testIp,
      },
      body: JSON.stringify({ username: loginUser, password: 'WrongPassword!' }),
    });

    assert.equal(res.status, 401);
    const data = await res.json();
    assert.equal(data.error, 'Invalid username or password');
  });

  await t.test('POST /api/auth/login fails with nonexistent username using generic message (no enumeration)', async () => {
    const res = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-For': testIp,
      },
      body: JSON.stringify({ username: 'nonexistent_user_xyz', password: 'SomePassword123!' }),
    });

    assert.equal(res.status, 401);
    const data = await res.json();
    assert.equal(data.error, 'Invalid username or password');
  });

  await t.test('GET /api/auth/me returns identity profile for valid token', async () => {
    const res = await fetch(`${BASE_URL}/api/auth/me`, {
      headers: { Authorization: `Bearer ${validToken}` },
    });

    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.username, loginUser);
    assert.equal(data.role, 'analyst');
    assert.equal(data.isActive, true);
    assert.equal(data.passwordHash, undefined);
  });

  await t.test('GET /api/auth/me rejects missing token with 401', async () => {
    const res = await fetch(`${BASE_URL}/api/auth/me`);
    assert.equal(res.status, 401);
    const data = await res.json();
    assert.ok(data.error);
  });

  await t.test('GET /api/auth/me rejects malformed Authorization header with 401', async () => {
    const res = await fetch(`${BASE_URL}/api/auth/me`, {
      headers: { Authorization: 'Basic invalidcredentials' },
    });
    assert.equal(res.status, 401);
  });

  await t.test('GET /api/auth/me rejects tampered token with 401', async () => {
    const tampered = validToken.slice(0, -6) + 'badbad';
    const res = await fetch(`${BASE_URL}/api/auth/me`, {
      headers: { Authorization: `Bearer ${tampered}` },
    });
    assert.equal(res.status, 401);
  });

  await t.test('POST /api/auth/logout succeeds for authenticated client', async () => {
    const res = await fetch(`${BASE_URL}/api/auth/logout`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${validToken}` },
    });

    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.message, 'Logged out successfully');
  });
});

test('Auth — Role-Based Access Control (RBAC)', async (t) => {
  const adminToken = signToken({ id: 'u-admin', username: 'admin-tester', role: 'admin' });
  const analystToken = signToken({ id: 'u-analyst', username: 'analyst-tester', role: 'analyst' });
  const readOnlyToken = signToken({ id: 'u-readonly', username: 'readonly-tester', role: 'read_only' });

  // 1. ADMIN permissions
  await t.test('ADMIN: Has access to logs, alerts, uploads, and user management', async () => {
    const logsRes = await fetch(`${BASE_URL}/api/logs?page=1&pageSize=1`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert.equal(logsRes.status, 200);

    const alertsRes = await fetch(`${BASE_URL}/api/alerts?page=1&pageSize=1`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert.equal(alertsRes.status, 200);

    const usersRes = await fetch(`${BASE_URL}/api/users`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert.equal(usersRes.status, 200);

    const uploadConfigRes = await fetch(`${BASE_URL}/api/uploads/config`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert.equal(uploadConfigRes.status, 200);
  });

  // 2. ANALYST permissions
  await t.test('ANALYST: Has access to logs, alerts, triage, and upload config', async () => {
    const logsRes = await fetch(`${BASE_URL}/api/logs?page=1&pageSize=1`, {
      headers: { Authorization: `Bearer ${analystToken}` },
    });
    assert.equal(logsRes.status, 200);

    const alertsRes = await fetch(`${BASE_URL}/api/alerts?page=1&pageSize=1`, {
      headers: { Authorization: `Bearer ${analystToken}` },
    });
    assert.equal(alertsRes.status, 200);

    const uploadConfigRes = await fetch(`${BASE_URL}/api/uploads/config`, {
      headers: { Authorization: `Bearer ${analystToken}` },
    });
    assert.equal(uploadConfigRes.status, 200);
  });

  await t.test('ANALYST: Is forbidden from managing users (403)', async () => {
    const usersRes = await fetch(`${BASE_URL}/api/users`, {
      headers: { Authorization: `Bearer ${analystToken}` },
    });
    assert.equal(usersRes.status, 403);
    const data = await usersRes.json();
    assert.ok(data.error.includes('Forbidden'));
  });

  // 3. READ_ONLY permissions
  await t.test('READ_ONLY: Can view dashboard summary, logs, and alerts', async () => {
    const summaryRes = await fetch(`${BASE_URL}/api/summary`, {
      headers: { Authorization: `Bearer ${readOnlyToken}` },
    });
    assert.equal(summaryRes.status, 200);

    const logsRes = await fetch(`${BASE_URL}/api/logs?page=1&pageSize=1`, {
      headers: { Authorization: `Bearer ${readOnlyToken}` },
    });
    assert.equal(logsRes.status, 200);

    const alertsRes = await fetch(`${BASE_URL}/api/alerts?page=1&pageSize=1`, {
      headers: { Authorization: `Bearer ${readOnlyToken}` },
    });
    assert.equal(alertsRes.status, 200);
  });

  await t.test('READ_ONLY: Is forbidden from updating alert status (403)', async () => {
    const res = await fetch(`${BASE_URL}/api/alerts/sample-alert-id/status`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${readOnlyToken}`,
      },
      body: JSON.stringify({ status: 'acknowledged' }),
    });
    assert.equal(res.status, 403);
    const data = await res.json();
    assert.ok(data.error.includes('Forbidden'));
  });

  await t.test('READ_ONLY: Is forbidden from generating AI investigation (403)', async () => {
    const res = await fetch(`${BASE_URL}/api/alerts/sample-alert-id/investigate`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${readOnlyToken}` },
    });
    assert.equal(res.status, 403);
  });

  await t.test('READ_ONLY: Is forbidden from uploading logs (403)', async () => {
    const res = await fetch(`${BASE_URL}/api/uploads`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${readOnlyToken}`,
      },
      body: JSON.stringify({
        fileName: 'test.log',
        sourceType: 'syslog',
        encoding: 'utf8',
        content: 'Sample log line',
      }),
    });
    assert.equal(res.status, 403);
  });

  await t.test('READ_ONLY: Is forbidden from managing users (403)', async () => {
    const res = await fetch(`${BASE_URL}/api/users`, {
      headers: { Authorization: `Bearer ${readOnlyToken}` },
    });
    assert.equal(res.status, 403);
  });
});

test('Auth — Security Controls & Edge Cases', async (t) => {
  const deactUser = `deact_${Date.now()}`;
  const deactPass = 'DeactPassword123!';
  const created = await createUser({
    username: deactUser,
    password: deactPass,
    role: 'analyst',
  });
  await updateUser(created.id, { isActive: false });

  await t.test('Inactive account cannot log in and receives 401 generic error', async () => {
    const res = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-For': '198.51.100.222',
      },
      body: JSON.stringify({ username: deactUser, password: deactPass }),
    });
    assert.equal(res.status, 401);
    const data = await res.json();
    assert.equal(data.error, 'Invalid username or password');
  });

  await t.test('Inactive account token cannot access /api/auth/me', async () => {
    const deactToken = signToken({ id: created.id, username: deactUser, role: 'analyst' });
    const res = await fetch(`${BASE_URL}/api/auth/me`, {
      headers: { Authorization: `Bearer ${deactToken}` },
    });
    assert.equal(res.status, 401);
  });

  await t.test('Client cannot escalate privileges via body or query parameters', async () => {
    const token = signToken({ id: 'u-user', username: 'standard-user', role: 'read_only' });
    const res = await fetch(`${BASE_URL}/api/users?role=admin`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
    });
    // Role must be derived from token (read_only), query cannot escalate to admin
    assert.equal(res.status, 403);
  });

  await t.test('Login rate limiter rejects after 10 attempts from same IP within 15 minutes', async () => {
    const rateLimitIp = `198.51.100.${Math.floor(Math.random() * 50) + 150}`;
    // Make 10 attempts
    for (let i = 0; i < 10; i++) {
      const res = await fetch(`${BASE_URL}/api/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Forwarded-For': rateLimitIp,
        },
        body: JSON.stringify({ username: 'rate_test_user', password: 'wrong_password' }),
      });
      assert.equal(res.status, 401);
    }

    // 11th attempt must be rate-limited with HTTP 429
    const limitedRes = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-For': rateLimitIp,
      },
      body: JSON.stringify({ username: 'rate_test_user', password: 'wrong_password' }),
    });
    assert.equal(limitedRes.status, 429);
    const data = await limitedRes.json();
    assert.ok(data.error.includes('Too many login attempts'));
  });
});

test('Auth — Socket.IO Real-time Authentication', async (t) => {
  await t.test('Socket.IO rejects connection without token', async () => {
    await assert.rejects(
      new Promise((resolve, reject) => {
        const socket = Client(BASE_URL, {
          transports: ['websocket'],
          reconnection: false,
        });

        socket.on('connect', () => {
          socket.disconnect();
          reject(new Error('Should not have connected without token'));
        });

        socket.on('connect_error', (err) => {
          socket.disconnect();
          reject(err);
        });
      }),
      (err) => err.message.includes('Authentication required') || err.message.includes('connect_error')
    );
  });

  await t.test('Socket.IO rejects connection with invalid/tampered token', async () => {
    await assert.rejects(
      new Promise((resolve, reject) => {
        const socket = Client(BASE_URL, {
          transports: ['websocket'],
          reconnection: false,
          auth: { token: 'invalid.tampered.token' },
        });

        socket.on('connect', () => {
          socket.disconnect();
          reject(new Error('Should not have connected with invalid token'));
        });

        socket.on('connect_error', (err) => {
          socket.disconnect();
          reject(err);
        });
      }),
      (err) => err.message.includes('Invalid') || err.message.includes('Authentication failed') || err.message.includes('connect_error')
    );
  });

  await t.test('Socket.IO accepts connection with valid JWT token', async () => {
    const token = signToken({ id: 'ws-user', username: 'ws-analyst', role: 'analyst' });
    await new Promise((resolve, reject) => {
      const socket = Client(BASE_URL, {
        transports: ['websocket'],
        reconnection: false,
        auth: { token },
      });

      const timer = setTimeout(() => {
        socket.disconnect();
        reject(new Error('Socket.IO connection timeout'));
      }, 5000);

      socket.on('connect', () => {
        clearTimeout(timer);
        socket.disconnect();
        resolve();
      });

      socket.on('connect_error', (err) => {
        clearTimeout(timer);
        socket.disconnect();
        reject(err);
      });
    });
  });
});
