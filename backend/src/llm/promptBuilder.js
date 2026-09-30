// backend/src/llm/promptBuilder.js

import { INVESTIGATION_SCHEMA } from "./schema.js";

export const PROMPT_VERSION = 1;

export function buildInvestigationPrompt(alert) {

    const evidence = JSON.stringify(
        alert.evidence?.slice(0,5) ?? [],
        null,
        2
    );

    return `
You are a Tier-3 SOC Analyst.

Investigate the following security alert.

Your task is to perform an incident investigation.

Use cybersecurity best practices.

Use MITRE ATT&CK knowledge.

Use only the supplied evidence.

Never invent missing information.

${INVESTIGATION_SCHEMA}

Alert

Rule:
${alert.rule_name}

Rule ID:
${alert.rule_id}

Severity:
${alert.severity}

Host:
${alert.affected_host}

User:
${alert.affected_user}

Source IP:
${alert.source_ip}

MITRE Technique

${alert.mitre_technique_id}

${alert.mitre_technique_name}

${alert.mitre_tactic}

Evidence

${evidence}
`;
}