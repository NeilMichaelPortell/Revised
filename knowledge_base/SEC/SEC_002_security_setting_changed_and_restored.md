# Security Setting Changed and Restored

**ID:** SEC_002 | **Category:** SEC | **Type:** contrastive diagnostic guidance

<!-- Document ID: SEC_002 -->

## Summary
Explains how to treat a security setting that was changed and then restored.

## Observable conditions
- `defender_config_changed = true`
- `verified_activity_context.defender_change` indicates the setting was later restored

## Normal / benign reading
Restoring a changed setting is a positive action and should be recorded, but restoration does not erase that a change occurred.

## Abnormal reading
A configuration change remains a security-relevant event even if reverted; the temporary window of reduced protection is the concern.

## Severity
| Severity | When it applies |
|----------|-----------------|
| Low | not applicable on its own |
| Medium | A configuration setting was changed temporarily and restored, with no other risk signal. |
| High | A change accompanied by another risky action during the reduced-protection window. |
| Critical | Only with several security-control changes or execution during the window. |

## Expected indicators
- defender_configuration_changed
- security_setting_restored
- defender_enabled
- no_additional_risky_activity

## False-positive checks
- Restoration is positive, but it does not erase that a change occurred; do not downgrade to low because it was reverted.
- Do not treat a documented, reverted test change as an active compromise.

## Evidence combinations
Change plus restore with nothing else is medium. A risky action during the window raises severity.

## Analyst notes
- Judge only on evidence present in the structured input; absent evidence is not positive evidence.
- Visibility is not execution; an opened interface is not a change; a restored setting does not erase the original change.
- Do not use scenario or category identifiers to decide the classification.

## Examples
- Benign: A Defender setting is changed for a test and restored shortly after, with no other activity.
- Abnormal: A setting is changed and, during the window, a script is executed.

## Related records
SEC_001, SEC_003, SEC_005
