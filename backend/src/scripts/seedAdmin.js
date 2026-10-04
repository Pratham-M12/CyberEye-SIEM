// backend/src/scripts/seedAdmin.js
import 'dotenv/config';
import { pingElasticsearch } from '../es/client.js';
import { ensureIndices } from '../es/indices.js';
import { countActiveAdmins, createUser, getUserByUsername } from '../services/userService.js';

/**
 * Checks for existing admin accounts and seeds the initial administrator if configured in .env.
 * Does not overwrite existing accounts and strictly requires non-empty environment credentials.
 */
export async function seedAdmin() {
  const username = process.env.INITIAL_ADMIN_USERNAME;
  const password = process.env.INITIAL_ADMIN_PASSWORD;

  if (!username || !password || password === 'replace_me' || password === 'API required here') {
    console.log('[seedAdmin] Initial admin setup skipped: INITIAL_ADMIN_USERNAME and INITIAL_ADMIN_PASSWORD must be configured in .env');
    return false;
  }

  const adminCount = await countActiveAdmins();
  if (adminCount > 0) {
    console.log(`[seedAdmin] Administrator account already exists (${adminCount} active admin(s)). Skipping.`);
    return false;
  }

  const existing = await getUserByUsername(username, false);
  if (existing) {
    console.log(`[seedAdmin] User "${username}" already exists. Skipping.`);
    return false;
  }

  const admin = await createUser({
    username,
    password,
    role: 'admin',
  });

  console.log(`[seedAdmin] Successfully provisioned initial administrator account: "${admin.username}"`);
  return true;
}

// Allow direct standalone CLI execution: node src/scripts/seedAdmin.js
if (process.argv[1] && process.argv[1].endsWith('seedAdmin.js')) {
  (async () => {
    const alive = await pingElasticsearch();
    if (!alive) {
      console.error('[seedAdmin] Could not reach Elasticsearch.');
      process.exit(1);
    }
    await ensureIndices();
    await seedAdmin();
    process.exit(0);
  })().catch((err) => {
    console.error('[seedAdmin] Failed:', err.message);
    process.exit(1);
  });
}
