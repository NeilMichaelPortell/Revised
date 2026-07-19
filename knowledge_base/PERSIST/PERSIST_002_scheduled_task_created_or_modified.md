# Scheduled Task Created or Modified

**ID:** PERSIST_002 | **Category:** PERSIST | **Type:** abnormal single-signal guidance

<!-- Document ID: PERSIST_002 -->

## Summary
Explains interpretation of creating or modifying a scheduled task.

## Observable conditions
- `scheduled_task_change = true`
- `verified_activity_context` or `scheduled_task_details` indicate a task was created or modified

## Normal / benign reading
A sanctioned administrative or software-driven scheduled task may be legitimate, but legitimacy should be supported by context rather than assumed.

## Abnormal reading
Creating or modifying a scheduled task is a common persistence mechanism and is a confirmed risky action when unexplained.

## Severity
| Severity | When it applies |
|----------|-----------------|
| Low | not applicable on its own |
| Medium | A single documented task change with a plausible benign explanation. |
| High | An unexplained task creation or modification. |
| Critical | Task creation combined with disabled protection or execution. |

## Expected indicators
- scheduled_task_created
- scheduled_task_modified
- task_scheduler_viewed

## False-positive checks
- A sanctioned administrative or software-driven task may be legitimate; require context before assuming malice.
- Do not treat a documented maintenance task as critical on its own.

## Evidence combinations
One unexplained change is high. With disabled protection or execution it approaches critical.

## Analyst notes
- Judge only on evidence present in the structured input; absent evidence is not positive evidence.
- Visibility is not execution; an opened interface is not a change; a restored setting does not erase the original change.
- Do not use scenario or category identifiers to decide the classification.

## Examples
- Benign: A documented maintenance task is created as part of a sanctioned deployment with supporting context.
- Abnormal: A scheduled task is created with no sanctioned explanation.

## Related records
PERSIST_001, PERSIST_003, PERSIST_005
