# Scheduled Task Deleted or Test Cleanup

**ID:** PERSIST_003 | **Category:** PERSIST | **Type:** contrastive diagnostic guidance

<!-- Document ID: PERSIST_003 -->

## Summary
Explains how to treat deletion of a scheduled task or removal of a harmless test artefact.

## Observable conditions
- `scheduled_task_change = true` and the change was a deletion
- `verified_activity_context` indicates cleanup of a test artefact

## Normal / benign reading
Removing a harmless test task or cleaning up a previously created test artefact is maintenance activity, not persistence creation.

## Abnormal reading
Deletion becomes relevant if it is used to remove evidence of a prior risky change, or if it accompanies other risky signals.

## Severity
| Severity | When it applies |
|----------|-----------------|
| Low | A harmless test task is deleted as cleanup. |
| Medium | A deletion whose purpose is unclear, with no other signal. |
| High | A deletion accompanying other risky evidence. |
| Critical | Only as part of a broader compound pattern. |

## Expected indicators
- scheduled_task_deleted
- cleanup_activity
- no_persistence_change
- no_additional_risky_activity

## False-positive checks
- Removing a harmless test task is cleanup, not persistence creation.
- Escalate only if deletion appears to remove evidence of a prior risky change or co-occurs with other risk.

## Evidence combinations
Cleanup deletion is low. Deletion alongside other risky signals raises severity.

## Analyst notes
- Judge only on evidence present in the structured input; absent evidence is not positive evidence.
- Visibility is not execution; an opened interface is not a change; a restored setting does not erase the original change.
- Do not use scenario or category identifiers to decide the classification.

## Examples
- Benign: A test scheduled task created earlier is deleted as cleanup.
- Abnormal: A task is deleted immediately after disabled protection, suggesting evidence removal.

## Related records
PERSIST_002, PERSIST_004, NORMAL_004
