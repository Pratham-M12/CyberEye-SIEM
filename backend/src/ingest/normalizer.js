import { esClient } from '../es/client.js';

/**
 * Winlogbeat, Filebeat, and Auditbeat all ship events directly to
 * Elasticsearch — the Node backend never sits in that hot path. Normalization
 * ("raw log source -> common schema") therefore happens as an Elasticsearch
 * Ingest Pipeline, referenced by each Beat's `output.elasticsearch.pipeline`
 * (or per-input `pipeline:`) setting. This file defines and registers those
 * pipelines. See filebeat/filebeat.yml and winlogbeat/winlogbeat.yml for the
 * config that points each input at the matching pipeline below.
 *
 * Every pipeline's job is the same: read whatever ECS fields the Beat module
 * already populated, and set our common schema fields on top:
 *   @timestamp, source.ip, destination.ip, destination.port, event.type,
 *   event.severity, host.name, user.name, log.source, raw_message
 */

const WINDOWS_EVENT_ID_MAP = {
  4624: { type: 'auth_success', severity: 'low' },
  4625: { type: 'auth_failure', severity: 'medium' },
  4672: { type: 'privilege_assigned', severity: 'high' },
  4688: { type: 'process_create', severity: 'low' },
};

const windowsPipeline = {
  id: 'siem-windows-normalize',
  description: 'Normalize Winlogbeat Windows Security events into the common SIEM schema',
  processors: [
    { set: { field: 'log.source', value: 'windows' } },
    {
      set: {
        field: 'event.id',
        value: '{{winlog.event_id}}',
        ignore_empty_value: true,
      },
    },
    {
      set: {
        field: 'host.name',
        value: '{{winlog.computer_name}}',
        ignore_empty_value: true,
      },
    },
    {
      set: {
        field: 'user.name',
        value: '{{winlog.event_data.TargetUserName}}',
        ignore_empty_value: true,
      },
    },
    {
      set: {
        field: 'user.name',
        value: '{{winlog.event_data.SubjectUserName}}',
        ignore_empty_value: true,
        if: 'ctx.user == null || ctx.user.name == null || ctx.user.name == "" || ctx.user.name == "-"',
      },
    },
    {
      set: {
        field: 'source.ip',
        value: '{{winlog.event_data.IpAddress}}',
        ignore_empty_value: true,
        if: 'ctx.winlog != null && ctx.winlog.event_data != null && ctx.winlog.event_data.IpAddress != null && ctx.winlog.event_data.IpAddress != "-" && ctx.winlog.event_data.IpAddress.trim() != ""',
      },
    },
    {
      remove: {
        field: 'source.ip',
        ignore_missing: true,
        if: 'ctx.source != null && (ctx.source.ip == "-" || ctx.source.ip == "")',
      },
    },
    {
      remove: {
        field: 'source',
        ignore_missing: true,
        if: 'ctx.source != null && ctx.source.isEmpty()',
      },
    },
    // Derive event.type / event.severity from the Windows Event ID.
    {
      script: {
        description: 'Map Windows Event ID -> event.type / event.severity',
        lang: 'painless',
        source: `
          def map = params.eventIdMap;
          if (ctx['event'] != null && ctx.event.id != null && map.containsKey(ctx.event.id)) {
            def m = map.get(ctx.event.id);
            ctx.event.type = m.type;
            ctx.event.severity = m.severity;
          }
        `,
        params: { eventIdMap: WINDOWS_EVENT_ID_MAP },
      },
    },
    {
      set: {
        field: 'raw_message',
        value: '{{message}}',
        ignore_empty_value: true,
      },
    },
  ],
};

const snortPipeline = {
  id: 'siem-snort-normalize',
  description: 'Normalize Snort IDS alert lines (shipped via Filebeat) into the common SIEM schema',
  processors: [
    { set: { field: 'log.source', value: 'snort' } },
    {
      set: {
        field: 'raw_message',
        value: '{{message}}',
        ignore_empty_value: true,
      },
    },
    {
      grok: {
        field: 'message',
        patterns: [
          '(?m)%{DATA}\\[Priority:\\s*%{NUMBER:_snort_priority}\\].*?\\{%{WORD:_snort_proto}\\}\\s+%{IP:source.ip}(?::%{NUMBER:source.port:int})?\\s*->\\s*%{IP:destination.ip}(?::%{NUMBER:destination.port:int})?',
          '(?m)\\[Priority:\\s*%{NUMBER:_snort_priority}\\].*?\\{%{WORD:_snort_proto}\\}\\s+%{IP:source.ip}(?::%{NUMBER:source.port:int})?\\s*->\\s*%{IP:destination.ip}(?::%{NUMBER:destination.port:int})?',
          '(?m)%{IP:source.ip}(?::%{NUMBER:source.port:int})?\\s*->\\s*%{IP:destination.ip}(?::%{NUMBER:destination.port:int})?',
        ],
        ignore_failure: true,
        if: 'ctx.destination == null || ctx.destination.port == null',
      },
    },
    {
      script: {
        description: 'Map Snort priority to severity and set default event type',
        lang: 'painless',
        source: `
          if (ctx.event == null) { ctx.event = new HashMap(); }
          if (ctx.event.type == null) { ctx.event.type = 'network_intrusion'; }
          if (ctx._snort_priority != null) {
            def p = ctx._snort_priority;
            if (p == '1') { ctx.event.severity = 'critical'; }
            else if (p == '2') { ctx.event.severity = 'high'; }
            else if (p == '3') { ctx.event.severity = 'medium'; }
            else { ctx.event.severity = 'low'; }
          } else if (ctx.event.severity == null) {
            ctx.event.severity = 'high';
          }
          ctx.remove('_snort_priority');
          ctx.remove('_snort_proto');
        `,
      },
    },
  ],
};

// SQLi / XSS detection patterns used by both the ingest pipeline (tagging)
// and rule R4 (alerting). Kept intentionally simple/portfolio-scope.
export const SQLI_XSS_REGEX =
  "(?i)(union\\s+select|or\\s+1=1|['\\\"]\\s*--|<script|javascript:|onerror\\s*=|drop\\s+table)";

const webPipeline = {
  id: 'siem-web-normalize',
  description: 'Normalize Apache/Nginx access logs (shipped via Filebeat) into the common SIEM schema',
  processors: [
    {
      set: {
        field: 'log.source',
        value: '{{event.module}}', // "nginx" or "apache"
        ignore_empty_value: true,
      },
    },
    {
      set: {
        field: 'raw_message',
        value: '{{message}}',
        ignore_empty_value: true,
      },
    },
    {
      set: {
        field: 'source.ip',
        value: '{{source.address}}',
        ignore_empty_value: true,
      },
    },
    {
      set: {
        field: 'http.uri',
        value: '{{url.original}}',
        ignore_empty_value: true,
      },
    },
    {
      grok: {
        field: 'message',
        patterns: [
          '%{IPORHOST:source.ip}\\s+\\S+\\s+\\S+\\s+\\[%{DATA}\\]\\s+"%{WORD:[_tmp][method]}\\s+%{NOTSPACE:http.uri}(?:\\s+HTTP/%{NUMBER:[_tmp][version]})?"',
          '%{IPORHOST:source.ip}\\s+\\S+\\s+\\S+\\s+\\[%{DATA}\\]\\s+"%{DATA:[_tmp][request]}"',
        ],
        ignore_failure: true,
        if: 'ctx.http == null || ctx.http.uri == null',
      },
    },
    {
      urldecode: {
        field: 'http.uri',
        ignore_missing: true,
      },
    },
    {
      script: {
        description: 'Set log.source fallback, flag likely SQLi/XSS payloads, and set event classification',
        lang: 'painless',
        source: `
          if (ctx.log == null || ctx.log.source == null) {
            if (ctx.event != null && ctx.event.module != null) {
              if (ctx.log == null) ctx.log = new HashMap();
              ctx.log.source = ctx.event.module;
            } else {
              if (ctx.log == null) ctx.log = new HashMap();
              ctx.log.source = 'nginx';
            }
          }
          if (ctx.event == null) { ctx.event = new HashMap(); }
          if (ctx.http != null && ctx.http.uri != null) {
            String u = ctx.http.uri.toLowerCase();
            boolean isAttack = (u.contains("union") && u.contains("select")) ||
                               (u.contains("or") && u.contains("1=1")) ||
                               u.contains("'--") || u.contains("\\"--") ||
                               u.contains("<script") || u.contains("javascript:") ||
                               u.contains("onerror") ||
                               (u.contains("drop") && u.contains("table"));
            if (isAttack) {
              ctx.event.type = 'web_attack';
              ctx.event.severity = 'medium';
            } else {
              ctx.event.type = 'web_request';
              ctx.event.severity = 'low';
            }
          } else {
            ctx.event.type = 'web_request';
            ctx.event.severity = 'low';
          }
          ctx.remove('_tmp');
        `,
      },
    },
  ],
};

const syslogPipeline = {
  id: 'siem-syslog-normalize',
  description: 'Normalize Linux syslog/auditd events (shipped via Filebeat) into the common SIEM schema',
  processors: [
    { set: { field: 'log.source', value: 'syslog' } },
    {
      set: {
        field: 'raw_message',
        value: '{{message}}',
        ignore_empty_value: true,
      },
    },
    {
      set: {
        field: 'host.name',
        value: '{{host.hostname}}',
        ignore_empty_value: true,
      },
    },
    {
      grok: {
        field: 'message',
        patterns: [
          '^(?:%{SYSLOGTIMESTAMP}|%{TIMESTAMP_ISO8601})\\s+%{HOSTNAME:host.name}\\s+',
        ],
        ignore_failure: true,
        if: 'ctx.host == null || ctx.host.name == null',
      },
    },
    {
      grok: {
        field: 'message',
        patterns: [
          'from %{IP:source.ip}',
          'rhost=%{IP:source.ip}',
          '\\[%{IP:source.ip}\\]',
        ],
        ignore_failure: true,
        if: 'ctx.source == null || ctx.source.ip == null',
      },
    },
    {
      grok: {
        field: 'message',
        patterns: [
          'for (?:invalid user )?%{USERNAME:user.name}\\s+from',
          'session opened for user %{USERNAME:user.name}',
          'user=%{USERNAME:user.name}\\b',
          '\\bUSER=%{USERNAME:user.name}\\b',
          'sudo:\\s+%{USERNAME:user.name}\\s+:',
        ],
        ignore_failure: true,
        if: 'ctx.user == null || ctx.user.name == null',
      },
    },
    {
      gsub: {
        field: 'user.name',
        pattern: '[(),;]',
        replacement: '',
        ignore_missing: true,
      },
    },
    {
      script: {
        description: 'Classify Linux authentication, privilege, and system events',
        lang: 'painless',
        source: `
          if (ctx.event == null) { ctx.event = new HashMap(); }
          String msg = ctx.message != null ? ctx.message.toLowerCase() : '';
          if (msg.contains("failed password") || msg.contains("authentication failure") || msg.contains("invalid user") || msg.contains("failed login")) {
            ctx.event.type = 'auth_failure';
            ctx.event.severity = 'medium';
          } else if (msg.contains("sudo:") || msg.contains("command=") || (msg.contains("session opened") && msg.contains("root"))) {
            ctx.event.type = 'privilege_assigned';
            ctx.event.severity = 'high';
          } else if (msg.contains("accepted password") || msg.contains("accepted publickey") || msg.contains("session opened") || msg.contains("authentication succeeded")) {
            ctx.event.type = 'auth_success';
            ctx.event.severity = 'low';
          } else {
            if (ctx.event.type == null) ctx.event.type = 'system_event';
            if (ctx.event.severity == null) ctx.event.severity = 'low';
          }
        `,
      },
    },
  ],
};

export const PIPELINES = [windowsPipeline, snortPipeline, webPipeline, syslogPipeline];

export async function registerNormalizerPipelines() {
  for (const pipeline of PIPELINES) {
    await esClient.ingest.putPipeline({
      id: pipeline.id,
      description: pipeline.description,
      processors: pipeline.processors,
    });
    console.log(`[ingest] registered pipeline "${pipeline.id}"`);
  }
}
