# Incident Report — Multiple Failed Logins Followed by Success

**Incident Number:** 96742fee-ae1e-4c58-8eba-d2d8b3b48a1b
**Severity:** high
**Detection Source:** Splunk ES
**Generated:** 2026-06-13T10:49:15.794353+00:00

## Timeline
- 2026-06-12 03:02:10+00:00 | Splunk ES | authentication_failure | Parsed authentication_failure from log line.
- 2026-06-12 03:02:14+00:00 | Splunk ES | authentication_failure | Parsed authentication_failure from log line.
- 2026-06-12 03:13:59+00:00 | Splunk ES | authentication_failure | Parsed authentication_failure from log line.
- 2026-06-12 03:14:22+00:00 | Splunk ES | authentication_success | Parsed authentication_success from log line.


## Scope
Affected assets: DC01
Affected users: admin

## Root Cause
Authentication failures preceding a success indicate a successful brute-force or password-guessing attempt.

## Impact
Domain controller targeted; potential domain compromise.

## Containment
- Recommend (approval-gated) blocking the malicious source IP at the perimeter
- Recommend (approval-gated) resetting credentials for the targeted account


## Eradication
- Remove any persistence mechanisms identified during DFIR


## Recovery
- Restore affected accounts and verify clean state before re-enabling


## Lessons Learned
- Enforce MFA and lockout thresholds on privileged accounts
