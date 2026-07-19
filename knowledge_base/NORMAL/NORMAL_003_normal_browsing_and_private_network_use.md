# Normal Browsing and Private Network Use

**ID:** NORMAL_003 | **Category:** NORMAL | **Type:** benign baseline guidance

<!-- Document ID: NORMAL_003 -->

## Summary
Explains that ordinary browsing and normal network profiles are not security events by themselves.

## Observable conditions
- `web_domains` shows ordinary browsing
- `network_profile` is private, or public with no other risk signal
- no scan, failed-login, or security-control evidence is present

## Normal / benign reading
Ordinary web browsing on a private network is normal. A public network profile on its own is a context, not a risk; it raises concern only when combined with other risky evidence.

## Abnormal reading
Network context becomes relevant when combined with scanning activity, failed-login activity, or disabled protection.

## Severity
| Severity | When it applies |
|----------|-----------------|
| Low | Ordinary browsing on a private network, or a public profile with no other risky signal. |
| Medium | A public profile combined with one limited risk signal may be considered under the relevant category's guidance. |
| High | not applicable on its own |
| Critical | not from this record alone; needs a compound signal |

## Expected indicators
- browser_activity
- normal_network_activity
- private_network
- public_network
- no_additional_risky_activity

## False-positive checks
- A public network profile alone is context, not a risk signal; do not flag it without a co-occurring risky action.
- Ordinary browsing on a private network is normal; do not treat common domains as suspicious.

## Evidence combinations
Public network alone stays low. Public network plus failed logins or scanning is covered by AUTH or NET guidance.

## Analyst notes
- Judge only on evidence present in the structured input; absent evidence is not positive evidence.
- Visibility is not execution; an opened interface is not a change; a restored setting does not erase the original change.
- Do not use scenario or category identifiers to decide the classification.

## Examples
- Benign: A user browses common sites on a private network with no other risk signals.
- Abnormal: A public network profile appears together with network-scan execution; NET guidance then applies.

## Related records
NET_001, NET_002, AUTH_001
