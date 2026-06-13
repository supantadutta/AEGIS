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

Report a vulnerability: open a private security advisory or contact the
maintainers; do not file public issues for sensitive reports.
