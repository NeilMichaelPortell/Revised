# Failed Logins With Additional Risk Context

**ID:** AUTH_005 | **Category:** AUTH | **Type:** compound-risk guidance

<!-- Document ID: AUTH_005 -->

## Summary
Explains how failed logins combine with other signals to raise severity.

## Observable conditions
- `failed_login_activity = true`
- at least one additional risk signal is present, such as a public network profile, scanning, or disabled protection

## Normal / benign reading
If the only signal is a limited number of failures with no genuine additional risk evidence, this compound guidance does not apply and the isolated or repeated-failure guidance is used.

## Abnormal reading
Failed logins alongside independent risky evidence indicate a stronger abnormal pattern than authentication failures alone.

## Severity
| Severity | When it applies |
|----------|-----------------|
| Low | not applicable on its own |
| Medium | Failed logins plus one limited additional context. |
| High | Failed logins plus a confirmed risky action such as a scan or disabled protection. |
| Critical | High-frequency failures combined with public-network exposure and scanning or disabled protection. |

## Expected indicators
- repeated_failed_logins
- high_failed_login_count
- public_network
- network_scan
- defender_disabled
- rapid_activity_window

## False-positive checks
- If the only signal is a limited number of failures with no genuine additional risk, use the single-signal AUTH guidance instead of this compound record.
- Do not manufacture a second risk signal to justify escalation.

## Evidence combinations
Each added severe signal raises severity; the combination is what justifies high or critical, not the count alone.

## Analyst notes
- Judge only on evidence present in the structured input; absent evidence is not positive evidence.
- Visibility is not execution; an opened interface is not a change; a restored setting does not erase the original change.
- Do not use scenario or category identifiers to decide the classification.

## Examples
- Benign: Failed logins appear with only a private network and no other risk signal, so this compound guidance does not apply.
- Abnormal: High-frequency failures occur on a public network with a network scan executed in the same window.

## Related records
AUTH_003, AUTH_004, NET_005
