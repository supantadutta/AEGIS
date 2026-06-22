# AEGIS Security Model

AEGIS is a **blue-team / defensive** platform. It will never perform
unauthorized offensive activity.

## What AEGIS will do
- Analyze logs, alerts, and provided artifacts (read-only).
- Generate detections (Sigma/SPL/KQL/CQL/Wazuh/Suricata/YARA) and SIEM queries.
- Triage alerts, enrich IOCs (local-first), build timelines, map to MITRE ATT&CK.
- Perform **safe static** malware triage (metadata/hashes/strings only).
- Write SOC, incident, customer, and executive reports.
- Draft response plans — but **execution of risky actions requires approval**.

## What AEGIS will NOT do
- Execute malware, dump credentials, scan/exploit real targets.
- Establish persistence, build evasion logic, or bypass security tools.
- Block IPs/domains, disable accounts, isolate endpoints, quarantine files, or
  modify production detections/configs **without explicit human approval**.

## Approval gates
Actions in `configs/security.yaml > approval_required_actions` pause the
orchestrator (`status="waiting_approval"`) and are only executed after a human
approves via `blue-orchestrator resume SESSION_ID` (or the dashboard).

## Data protection
- API keys/secrets are redacted before any logging or storage.
- Untrusted log / threat-intel content is wrapped and flagged as data, not
  instructions, before being shown to a model (prompt-injection mitigation).
- Confidential/restricted data is routed only to local/mock models unless
  `ALLOW_EXTERNAL_FOR_SENSITIVE=true`.

## Settings & secrets storage
- Provider/integration API keys set from the dashboard are written to a local
  `aegis_settings.json` created with `0600` permissions and **git-ignored**. Real
  environment variables always take precedence, so CI/container-injected secrets
  are never overwritten. Secret values are masked (last 4 chars) wherever the UI
  displays them.
- External threat-intel APIs are **opt-in**. The dashboard "Lookup"/"Test"
  buttons are explicit human actions; the automated investigation pipeline only
  makes live external calls when the operator enables `AEGIS_AUTO_LIVE_INTEL` (or
  approves the `external_enrichment_api` gate). A source is queried only when it
  is enabled, has a client, and its credentials are present.

Report a vulnerability: open a private security advisory or contact the
maintainers; do not file public issues for sensitive reports.
