// backend/src/llm/summarizer.js

import axios from 'axios';
import 'dotenv/config';

const CLAUDE_API_KEY = process.env.CLAUDE_API_KEY; // API required here
const CLAUDE_MODEL = process.env.CLAUDE_MODEL || 'claude-sonnet-4-6';
const CLAUDE_API_URL = 'https://api.anthropic.com/v1/messages';

/**
 * Generates a 3-sentence analyst summary for an alert: what happened, why
 * it's suspicious, and what to do next. Called on-demand when the Alert
 * Detail drawer opens (not pre-generated), per the project's constraint on
 * avoiding unnecessary API calls.
 */
export async function summarizeAlert(alert) {
  if (!CLAUDE_API_KEY || CLAUDE_API_KEY === 'API required here') {
    return {
      summary:
        'LLM summary unavailable: CLAUDE_API_KEY is not configured. Add a real key to backend/.env to enable AI-generated analyst summaries.',
      generated: false,
    };
  }

  const prompt = buildPrompt(alert);

  try {
    const res = await axios.post(
      CLAUDE_API_URL,
      {
        model: CLAUDE_MODEL,
        max_tokens: 300,
        messages: [{ role: 'user', content: prompt }],
      },
      {
        headers: {
          'x-api-key': CLAUDE_API_KEY,
          'anthropic-version': '2023-06-01',
          'content-type': 'application/json',
        },
        timeout: 15000,
      }
    );

    const summary = res.data?.content
      ?.filter((block) => block.type === 'text')
      .map((block) => block.text)
      .join(' ')
      .trim();

    return { summary: summary || 'No summary returned.', generated: true };
  } catch (err) {
    const safeMsg =
      err.response?.data?.error?.message ||
      (err.response?.status ? `HTTP ${err.response.status}` : err.message);
    throw new Error(`LLM summary failed: ${safeMsg}`);
  }
}

function buildPrompt(alert) {
  const evidenceSample = JSON.stringify(alert.evidence?.slice(0, 5) ?? [], null, 2);

  return `You are a SOC analyst assistant. Given the following fired detection rule alert and its supporting raw log evidence, write EXACTLY 3 sentences:
1. What happened (plain-language description of the activity).
2. Why it is suspicious (tie it to the rule logic / MITRE technique).
3. A concrete suggested next action for the analyst.

Alert:
- Rule: ${alert.rule_name} (${alert.rule_id})
- Severity: ${alert.severity}
- MITRE technique: ${alert.mitre_technique_id} — ${alert.mitre_technique_name} (${alert.mitre_tactic})
- Affected host: ${alert.affected_host ?? 'unknown'}
- Affected user: ${alert.affected_user ?? 'unknown'}
- Source IP: ${alert.source_ip ?? 'unknown'}

Evidence sample (raw normalized events):
${evidenceSample}

Respond with only the 3 sentences, no preamble, no markdown.`;
}
