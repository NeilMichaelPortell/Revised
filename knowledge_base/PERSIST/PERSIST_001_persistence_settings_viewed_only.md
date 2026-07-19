# Persistence Settings Viewed Only

**ID:** PERSIST_001 | **Category:** PERSIST | **Type:** benign baseline guidance

<!-- Document ID: PERSIST_001 -->

## Summary
Explains that viewing Task Scheduler, Services, or Startup settings is normal.

## Observable conditions
- `viewed_interface = task_scheduler`, or Services or Startup were viewed
- no task, service, or startup change is recorded

## Normal / benign reading
Opening Task Scheduler, the Services interface, or Startup applications to view them is normal administrative and troubleshooting activity.

## Abnormal reading
This becomes relevant only when a task, service, or startup item is actually created, modified, or deleted.

## Severity
| Severity | When it applies |
|----------|-----------------|
| Low | A persistence-related interface is viewed with no change. |
| Medium | not applicable on its own |
| High | Applies only when a genuine change is present. |
| Critical | not from this record alone; needs a compound signal |

## Expected indicators
- task_scheduler_viewed
- services_viewed
- startup_items_viewed
- no_persistence_change
- no_additional_risky_activity

## False-positive checks
- Opening Task Scheduler, Services, or Startup to view them is normal administration; viewing is not modifying.
- Do not treat an opened persistence-related interface as persistence creation.

## Evidence combinations
Viewing plus no change stays low. A recorded change moves to the relevant PERSIST guidance.

## Analyst notes
- Judge only on evidence present in the structured input; absent evidence is not positive evidence.
- Visibility is not execution; an opened interface is not a change; a restored setting does not erase the original change.
- Do not use scenario or category identifiers to decide the classification.

## Examples
- Benign: Task Scheduler is opened and existing tasks are viewed with no change.
- Abnormal: Task Scheduler is opened and a new task is created; the task-creation guidance applies.

## Related records
PERSIST_002, PERSIST_004, NORMAL_004
