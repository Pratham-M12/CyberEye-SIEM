import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import SeverityBadge from './SeverityBadge.jsx';
import AlertTimeline from "./AlertTimeline.jsx";
import JsonViewer from "./JsonViewer.jsx";
import AIInvestigation from "./AIInvestigation.jsx";
import { getAlert, investigateAlert, setAlertStatus } from "../api/siem.js";
import { useAuth } from "../context/AuthContext.jsx";

const RULE_DESCRIPTIONS = {
  R1: 'Fires when a single source IP produces 5 or more failed Windows logins (Event ID 4625) within a 60 second window — the signature of an automated brute-force attempt.',
  R2: 'Escalation of R1: a brute-force burst from an IP followed by a successful login (Event ID 4624) from that same IP within 5 minutes — the credentials likely worked.',
  R3: 'Fires when a single source IP touches 10 or more distinct destination ports within 30 seconds, per Snort — typical of automated port/service discovery ahead of an intrusion attempt.',
  R4: "Fires when an Apache/Nginx request URI matches a known SQL injection or XSS pattern — someone is probing (or exploiting) a public-facing web application.",
  R5: 'Fires when a privilege is assigned (Event ID 4672) to a user within 5 minutes of that same user logging in (Event ID 4624) — a fast escalation-after-login pattern worth confirming was expected.',
};

const SUGGESTED_ACTIONS = {
  R1: 'Block the source IP at the perimeter firewall and confirm the targeted account has not been locked out or compromised.',
  R2: 'Force a password reset on the affected account immediately, block the source IP, and review the account for any activity since the successful login.',
  R3: 'Add the source IP to a watchlist, confirm whether it maps to a known vulnerability scanner, and block it if unauthorized.',
  R4: 'Inspect the web server access logs for a successful exploit response (200/500), apply a WAF rule for the matched pattern, and patch the vulnerable endpoint.',
  R5: 'Confirm the privilege grant was authorized (change ticket, admin request); if not, revoke it and investigate the account for compromise.',
};

function formatTime(ts) {
  if (!ts) return '—';
  return new Date(ts).toLocaleString();
}

export default function AlertDrawer({ alertId, onClose }) {
  const queryClient = useQueryClient();
  const { hasRole } = useAuth();
  const canTriage = hasRole('admin', 'analyst');

  const { data: alert, isLoading } = useQuery({
    queryKey: ['alert', alertId],
    queryFn: () => getAlert(alertId),
    enabled: Boolean(alertId),
  });

  const investigationMutation = useMutation({
    mutationFn: () => investigateAlert(alertId),

    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["alert", alertId],
      });
    },
  });

  const statusMutation = useMutation({
    mutationFn: (status) => setAlertStatus(alertId, status),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alert', alertId] });
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
    },
  });

  if (!alertId) return null;

  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-black/50" onClick={onClose}>
      <div
        className="h-full w-full max-w-2xl overflow-y-auto border-l border-hairline bg-panel"
        onClick={(e) => e.stopPropagation()}
      >
        {isLoading && <div className="p-6 text-sm text-ink-muted">Loading alert…</div>}

        {alert && (
          <div className="flex flex-col">
            <div className="flex items-start justify-between gap-4 border-b border-hairline p-5">
              <div>
                <div className="mb-2 flex items-center gap-2">
                  <SeverityBadge severity={alert.severity} />
                  <span className="font-mono text-[11px] text-ink-muted">{alert.rule_id}</span>
                </div>
                <h2 className="font-mono text-lg font-semibold text-ink-primary">{alert.rule_name}</h2>
                <p className="mt-1 font-mono text-xs text-ink-muted">{formatTime(alert['@timestamp'])}</p>
              </div>
              <button
                onClick={onClose}
                className="rounded-md border border-hairline px-2 py-1 font-mono text-xs text-ink-muted hover:text-ink-primary"
              >
                close
              </button>
            </div>

            <div className="space-y-6 p-5">
              <section>
                <h3 className="font-mono text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
                  Rule description
                </h3>
                <p className="mt-1.5 text-sm text-ink-primary">{RULE_DESCRIPTIONS[alert.rule_id]}</p>
              </section>

              <section className="grid grid-cols-2 gap-3">
                <Field label="Affected host" value={alert.affected_host} />
                <Field label="Affected user" value={alert.affected_user} />
                <Field label="Source IP" value={alert.source_ip} mono />
                <Field label="Status" value={alert.status} />
              </section>

              <section>
                <h3 className="font-mono text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
                  Incident Timeline
                </h3>

                <div className="mt-3 rounded-md border border-hairline bg-void p-4">
                  <AlertTimeline history={alert.history} />
                </div>
              </section>

              <section>
                <h3 className="font-mono text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
                  MITRE ATT&amp;CK
                </h3>
                <div className="mt-1.5 rounded-md border border-hairline bg-void p-3">
                  <p className="font-mono text-sm text-accent">
                    {alert.mitre_technique_id} — {alert.mitre_technique_name}
                  </p>
                  <p className="mt-0.5 text-xs text-ink-muted">Tactic: {alert.mitre_tactic}</p>
                </div>
              </section>

              <section>
                <div className="flex items-center justify-between">
                  <h3 className="font-mono text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
                    AI Investigation
                  </h3>
                  {canTriage && !investigationMutation.data && !alert.ai_investigation && (
                    <button
                      onClick={() => investigationMutation.mutate()}
                      disabled={investigationMutation.isPending}
                      className="rounded-md border border-accent/40 bg-accent/10 px-2.5 py-1 font-mono text-[11px] text-accent hover:bg-accent/20"
                    >
                      {
                        investigationMutation.isPending
                          ? "Investigating..."
                          : "🔍 Investigate"
                      }
                    </button>
                  )}
                  {!canTriage && !alert.ai_investigation && (
                    <span className="text-[11px] text-ink-muted italic">
                      Investigation restricted (Analyst/Admin only)
                    </span>
                  )}
                </div>
                <div className="mt-4">
                  <AIInvestigation
                    report={
                      investigationMutation.data?.investigation ??
                      alert.ai_investigation ??
                      null
                    }
                  />
                </div>
              </section>
              
              <section>
                <h3 className="font-mono text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
                  Suggested response action
                </h3>
                <p className="mt-1.5 rounded-md border border-severity-high/30 bg-severity-high/5 p-3 text-sm text-ink-primary">
                  {SUGGESTED_ACTIONS[alert.rule_id]}
                </p>
              </section>

              <section>
                <h3 className="font-mono text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
                  Contributing raw events ({alert.evidence?.length ?? 0})
                </h3>
                <div className="mt-1.5 space-y-2">
                  {(alert.evidence ?? []).map((event, idx) => (
                    <div key={idx} className="rounded-md border border-hairline bg-void p-2.5">
                      <div className="flex items-center justify-between font-mono text-[11px] text-ink-muted">
                        <span>{event['log.source']}</span>
                        <span className="tabular">{formatTime(event['@timestamp'])}</span>
                      </div>
                      <p className="mt-1 break-all font-mono text-xs text-ink-primary">
                        {event.raw_message || JSON.stringify(event)}
                      </p>
                    </div>
                  ))}
                </div>
              </section>

              <section>
                <h3 className="font-mono text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
                  Raw Alert JSON
                </h3>

                <div className="mt-3">
                  <JsonViewer data={alert} />
                </div>
              </section>

              <section className="border-t border-hairline pt-4">
                {canTriage ? (
                  <div className="flex gap-2">
                    {['acknowledged', 'closed', 'open'].map((status) => (
                      <button
                        key={status}
                        onClick={() => statusMutation.mutate(status)}
                        disabled={alert.status === status || statusMutation.isPending}
                        className="rounded-md border border-hairline px-3 py-1.5 font-mono text-xs capitalize text-ink-primary hover:border-accent disabled:opacity-30"
                      >
                        mark {status}
                      </button>
                    ))}
                  </div>
                ) : (
                  <div className="text-xs font-mono text-ink-muted italic">
                    Read-only role: Alert status triage is restricted to Analysts and Administrators.
                  </div>
                )}
              </section>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function Field({ label, value, mono }) {
  return (
    <div>
      <p className="font-mono text-[10px] uppercase tracking-wider text-ink-dim">{label}</p>
      <p className={`mt-0.5 text-sm text-ink-primary ${mono ? 'font-mono' : ''}`}>{value ?? '—'}</p>
    </div>
  );
}
