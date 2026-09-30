import cron from 'node-cron';
import 'dotenv/config';
import { writeAlerts } from '../alerts/writer.js';

import * as bruteForce from './bruteForce.js';
import * as credentialStuffing from './credentialStuffing.js';
import * as portScan from './portScan.js';
import * as webAttack from './webAttack.js';
import * as privEsc from './privEsc.js';

// Order matters slightly: credentialStuffing re-runs bruteForce's query
// internally, so running bruteForce first isn't required but keeps log
// output easy to follow.
const RULE_MODULES = [bruteForce, credentialStuffing, portScan, webAttack, privEsc];

const CRON_EXPRESSION = process.env.RULE_ENGINE_CRON || '*/30 * * * * *';

/**
 * Every 30 seconds, runs each detection rule's Elasticsearch aggregation
 * query, then writes any newly-fired alerts and pushes them to the frontend
 * over WebSocket. Rules are stateless - everything they need lives in
 * Elasticsearch - so a backend restart never loses in-flight detection
 * state.
 */
export function startRuleEngine(io) {
  console.log(`[rules] engine starting, schedule: "${CRON_EXPRESSION}"`);

  cron.schedule(CRON_EXPRESSION, () => {
    runAllRules(io).catch((err) => console.error('[rules] engine tick failed:', err));
  });
}

export async function runAllRules(io) {
  const tickStart = Date.now();
  let totalFired = 0;

  for (const rule of RULE_MODULES) {
    try {
      const candidates = await rule.run();
      if (candidates.length === 0) continue;

      const written = await writeAlerts(candidates, io);
      totalFired += written.length;

      if (written.length > 0) {
        console.log(`[rules] ${rule.RULE_ID} "${rule.RULE_NAME}" fired ${written.length} alert(s)`);
      }
    } catch (err) {
      console.error(`[rules] ${rule.RULE_ID} failed:`, err.message);
    }
  }

  const elapsedMs = Date.now() - tickStart;
  if (totalFired > 0) {
    console.log(`[rules] tick complete: ${totalFired} alert(s) in ${elapsedMs}ms`);
  }

  return { totalFired, elapsedMs };
}
