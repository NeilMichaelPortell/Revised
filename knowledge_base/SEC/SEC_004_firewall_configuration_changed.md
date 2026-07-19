# Firewall Configuration Changed

**ID:** SEC_004 | **Category:** SEC | **Type:** abnormal single-signal guidance

<!-- Document ID: SEC_004 -->

## Summary
Explains interpretation of a firewall configuration change.

## Observable conditions
- a firewall configuration change is recorded in `firewall_events`
- or a firewall profile state changed

## Normal / benign reading
An administrator making a sanctioned, documented firewall change may be legitimate, but this requires supporting evidence rather than assumption.

## Abnormal reading
An unexplained firewall configuration change weakens network protection and is a security-relevant action.

## Severity
| Severity | When it applies |
|----------|-----------------|
| Low | not applicable on its own |
| Medium | A single documented or minor firewall change with no other risk signal. |
| High | An unexplained firewall change, or one alongside another risk signal. |
| Critical | Firewall changes combined with disabled protection or other security-control changes. |

## Expected indicators
- firewall_configuration_changed
- defender_disabled
- no_additional_risky_activity

## False-positive checks
- A sanctioned, documented firewall change may be legitimate; require supporting context before assuming benign.
- Do not treat every firewall change as automatically critical.

## Evidence combinations
One change alone is medium to high depending on context; combined with disabled protection it is critical.

## Analyst notes
- Judge only on evidence present in the structured input; absent evidence is not positive evidence.
- Visibility is not execution; an opened interface is not a change; a restored setting does not erase the original change.
- Do not use scenario or category identifiers to decide the classification.

## Examples
- Benign: A documented administrative firewall rule update is recorded with supporting context.
- Abnormal: A firewall profile is turned off with no sanctioned explanation and alongside disabled Defender.

## Related records
SEC_003, SEC_005, NET_002
