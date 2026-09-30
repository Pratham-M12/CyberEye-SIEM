// Hardcoded MITRE ATT&CK mapping, one entry per detection rule.
// Attached to every alert written by alerts/writer.js.
export const MITRE_MAP = {
  R1: { id: 'T1110', name: 'Brute Force', tactic: 'Credential Access' },
  R2: { id: 'T1110', name: 'Brute Force', tactic: 'Credential Access' },
  R3: { id: 'T1046', name: 'Network Service Discovery', tactic: 'Discovery' },
  R4: { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
  R5: { id: 'T1078', name: 'Valid Accounts', tactic: 'Privilege Escalation' },
};
