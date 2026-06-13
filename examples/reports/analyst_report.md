# SOC Analyst Note — Multiple Failed Logins Followed by Success

**Session:** 96742fee-ae1e-4c58-8eba-d2d8b3b48a1b
**Generated:** 2026-06-13T10:49:15.790332+00:00
**Classification:** Confirmed Incident
**Severity:** high   **Confidence:** 0.74

## Alert Summary
src_ip=45.143.220.0, user=admin

## Key Evidence
- note: Triage summary: Triage of 'Multiple Failed Logins Followed by Success': observed activity involving source IP 45.143.220
- threat_intel: 45.143.220.0: Matched local blocklist: Brute-force source observed in honeypots
- timeline: Built timeline with 4 event(s).
- detection_rule: Generated successful-login-after-failures detection + 3 queries.
- report: # SOC Analyst Note — Multiple Failed Logins Followed by Success

**Session:** 96742fee-ae1e-4c58-8eba-d2d8b3b48a1b
**Gen


## Investigation Steps
1. Intake & Triage
2. Threat Intel Enrichment
3. Timeline Construction
4. Detection Engineering
5. Response Recommendation
6. Reporting


## Findings
- Entities involved in Multiple Failed Logins Followed by Success: src_ip=45.143.220.0, user=admin
- Failed logins followed by success: Authentication failures preceding a success indicate a successful brute-force or password-guessing attempt.


## MITRE ATT&CK Mapping
- T1110 Brute Force (Credential Access) — conf 0.74


## Recommended Actions
- Deploy/tune detection for 'successful-login-after-failures' (Successful Login After Repeated Failures); see false-positive notes before enabling in production.
- Increase monitoring on the affected accounts/assets for recurrence.


## Closure Note
Pattern matches known malicious behavior for this alert type.