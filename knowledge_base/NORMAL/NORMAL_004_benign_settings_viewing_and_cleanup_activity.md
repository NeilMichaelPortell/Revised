# Benign Settings Viewing and Cleanup Activity

**ID:** NORMAL_004 | **Category:** NORMAL | **Type:** benign baseline guidance

<!-- Document ID: NORMAL_004 -->

## Summary
Explains that viewing settings interfaces and removing harmless test artefacts are normal maintenance actions.

## Observable conditions
- `viewed_interface` is a settings interface opened for viewing
- no configuration change is recorded
- `verified_activity_context.startup_action = removed`, or a `scheduled_task_change` deletion, reverts a harmless test artefact

## Normal / benign reading
Opening a settings interface such as Windows Security, Task Scheduler, or network settings to view it is normal. Removing a harmless test artefact is cleanup, not a risky change.

## Abnormal reading
This becomes relevant only if a setting is actually changed, protection is disabled, or a persistence mechanism is created, each of which has separate evidence.

## Severity
| Severity | When it applies |
|----------|-----------------|
| Low | A settings interface is viewed with no change, or a harmless test artefact is removed. |
| Medium | not applicable on its own |
| High | Applies only when a genuine configuration change is present. |
| Critical | not from this record alone; needs a compound signal |

## Expected indicators
- settings_viewed
- cleanup_activity
- no_security_change
- no_persistence_change
- no_additional_risky_activity

## False-positive checks
- Opening a settings interface is not changing a setting; require a recorded change before escalating.
- Removing a harmless test artefact is cleanup, not a persistence or tampering event.

## Evidence combinations
Viewing plus no change stays low. A recorded change moves interpretation to SEC or PERSIST guidance.

## Analyst notes
- Judge only on evidence present in the structured input; absent evidence is not positive evidence.
- Visibility is not execution; an opened interface is not a change; a restored setting does not erase the original change.
- Do not use scenario or category identifiers to decide the classification.

## Examples
- Benign: Windows Security is opened and viewed with no setting changed.
- Abnormal: A settings interface is opened and a separate field records Defender being disabled; SEC guidance then applies.

## Related records
SEC_001, PERSIST_001, NET_003
