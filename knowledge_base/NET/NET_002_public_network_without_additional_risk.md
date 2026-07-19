# Public Network Without Additional Risk

**ID:** NET_002 | **Category:** NET | **Type:** contrastive diagnostic guidance

<!-- Document ID: NET_002 -->

## Summary
Explains that a public network profile alone is a context, not an abnormal signal.

## Observable conditions
- `network_profile` is public
- no other risk signal is present

## Normal / benign reading
Using a public network profile, for example at a cafe or airport, is common and is not abnormal on its own.

## Abnormal reading
A public profile raises severity only when combined with failed logins, scanning, disabled protection, or other risky evidence.

## Severity
| Severity | When it applies |
|----------|-----------------|
| Low | A public network profile with no other risk signal. |
| Medium | A public profile combined with one limited risk signal. |
| High | A public profile combined with a confirmed risky action. |
| Critical | A public profile combined with several severe signals such as scanning and disabled protection. |

## Expected indicators
- public_network
- normal_network_activity
- no_additional_risky_activity

## False-positive checks
- A public network profile alone is common and not abnormal; require a co-occurring risky signal before escalating.
- Do not treat 'public network' as equivalent to 'attack in progress'.

## Evidence combinations
Public alone is low. Public plus failed logins or scanning escalates under AUTH or the NET scan documents.

## Analyst notes
- Judge only on evidence present in the structured input; absent evidence is not positive evidence.
- Visibility is not execution; an opened interface is not a change; a restored setting does not erase the original change.
- Do not use scenario or category identifiers to decide the classification.

## Examples
- Benign: A laptop connects to a public network and browses normally with no other risk signal.
- Abnormal: A public profile appears with high-frequency failed logins and a network scan.

## Related records
NET_001, NET_005, AUTH_005
