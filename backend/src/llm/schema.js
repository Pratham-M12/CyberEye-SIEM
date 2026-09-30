// backend/src/llm/schema.js

export const INVESTIGATION_SCHEMA = `
Return ONLY valid JSON.

Schema:

{
  "executiveSummary": "string",

  "threatLevel": "LOW | MEDIUM | HIGH | CRITICAL",

  "confidence": number,

  "attackChain": [
    "string"
  ],

  "iocs": [
    "string"
  ],

  "mitre": {
    "technique": "string",
    "tactic": "string"
  },

  "falsePositives": [
    "string"
  ],

  "containment": [
    "string"
  ],

  "recovery": [
    "string"
  ]
}

Rules:

- Do NOT wrap JSON inside markdown.
- Do NOT explain.
- Do NOT add extra fields.
- Confidence must be between 0 and 100.
`;