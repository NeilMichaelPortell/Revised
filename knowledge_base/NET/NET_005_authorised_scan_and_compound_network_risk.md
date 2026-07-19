# Authorised Scan and Compound Network Risk

**ID:** NET_005 | **Category:** NET | **Type:** compound-risk guidance

<!-- Document ID: NET_005 -->

## Summary
Explains how scanning combines with an authorised target or with other network risk to determine severity.

## Observable conditions
- a network scan executed
- either an authorised local target is indicated, or additional risk signals are present

## Normal / benign reading
A scan against an explicitly authorised local or loopback target, for example sanctioned testing, is risky activity but is not necessarily critical on its own.

## Abnormal reading
A scan combined with public-network exposure, failed logins, or disabled protection is a stronger compound abnormal pattern.

## Severity
| Severity | When it applies |
|----------|-----------------|
| Low | not applicable on its own |
| Medium | not applicable on its own |
| High | A scan against an authorised local target with no further escalation. |
| Critical | A scan combined with public-network exposure and authentication anomalies or disabled protection. |

## Expected indicators
- network_scan
- authorised_local_target
- public_network
- repeated_failed_logins
- high_failed_login_count
- defender_disabled

## False-positive checks
- A scan against an explicitly authorised local/loopback target is risky but not automatically critical.
- Do not treat an authorised test scan as a full compromise without additional signals.

## Evidence combinations
Authorised-target scan is high. Add public network plus failed logins or disabled protection for critical.

## Analyst notes
- Judge only on evidence present in the structured input; absent evidence is not positive evidence.
- Visibility is not execution; an opened interface is not a change; a restored setting does not erase the original change.
- Do not use scenario or category identifiers to decide the classification.

## Examples
- Benign: A sanctioned test scan targets an authorised loopback address with no other risk signal.
- Abnormal: A scan runs on a public network alongside high-frequency failed logins.

## Related records
NET_004, AUTH_005, SEC_003
