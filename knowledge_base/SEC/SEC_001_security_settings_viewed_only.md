# Security Settings Viewed Only

**ID:** SEC_001 | **Category:** SEC | **Type:** benign baseline guidance

<!-- Document ID: SEC_001 -->

## Summary
Explains that viewing security interfaces without changing them is normal.

## Observable conditions
- `viewed_interface = windows_security`
- `defender_config_changed = false` and `defender_disabled = false`

## Normal / benign reading
Opening Windows Security or checking Defender status for viewing is normal maintenance and awareness activity.

## Abnormal reading
This becomes abnormal only when a security control is actually changed, disabled, or reconfigured.

## Severity
| Severity | When it applies |
|----------|-----------------|
| Low | A security interface is viewed with no change recorded. |
| Medium | not applicable on its own |
| High | Applies only when a genuine change is present. |
| Critical | not from this record alone; needs a compound signal |

## Expected indicators
- security_history_viewed
- settings_viewed
- defender_enabled
- no_security_change

## False-positive checks
- Viewing Windows Security or checking Defender status is normal awareness activity; it is not a configuration change.
- Do not treat an opened security interface as tampering.

## Evidence combinations
Viewing plus no change stays low. A recorded change moves to the disabled or reconfigured guidance.

## Analyst notes
- Judge only on evidence present in the structured input; absent evidence is not positive evidence.
- Visibility is not execution; an opened interface is not a change; a restored setting does not erase the original change.
- Do not use scenario or category identifiers to decide the classification.

## Examples
- Benign: Windows Security is opened and the protection history is viewed with no change.
- Abnormal: The interface is opened and a separate field records Defender being disabled; the disabled-protection guidance applies.

## Related records
SEC_002, SEC_003, NORMAL_004
