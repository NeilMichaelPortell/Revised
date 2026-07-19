# Normal Private Network Use

**ID:** NET_001 | **Category:** NET | **Type:** benign baseline guidance

<!-- Document ID: NET_001 -->

## Summary
Establishes that ordinary use of a private network is normal.

## Observable conditions
- `network_profile` is private
- no scan, failed-login, or security signal is present

## Normal / benign reading
Ordinary connectivity and browsing on a private network profile is normal network activity.

## Abnormal reading
Network activity becomes relevant when scanning occurs, when a public profile combines with other risk, or when network settings are changed rather than viewed.

## Severity
| Severity | When it applies |
|----------|-----------------|
| Low | Ordinary use of a private network with no risky co-signal. |
| Medium | not applicable on its own |
| High | not applicable on its own |
| Critical | not from this record alone; needs a compound signal |

## Expected indicators
- private_network
- normal_network_activity
- no_additional_risky_activity

## False-positive checks
- Ordinary connectivity on a private network is normal; do not add a risk indicator for baseline network use.
- Escalate only when scanning, a non-private profile with risk, or a settings change is present.

## Evidence combinations
Private network alone is low. Scanning or compound public-network risk moves to other NET documents.

## Analyst notes
- Judge only on evidence present in the structured input; absent evidence is not positive evidence.
- Visibility is not execution; an opened interface is not a change; a restored setting does not erase the original change.
- Do not use scenario or category identifiers to decide the classification.

## Examples
- Benign: A device operates on a private network with ordinary connectivity and no scanning.
- Abnormal: A network scan is executed on the same device; the scan guidance then applies.

## Related records
NET_002, NET_003, NORMAL_003
