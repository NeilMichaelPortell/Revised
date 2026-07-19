# Service or Persistence Change With Security Risk

**ID:** PERSIST_005 | **Category:** PERSIST | **Type:** compound-risk guidance

<!-- Document ID: PERSIST_005 -->

## Summary
Explains how a service or persistence change combines with security weakening to raise severity.

## Observable conditions
- `service_change = true` or a persistence change is present
- an independent security signal is present, such as disabled protection

## Normal / benign reading
If only a settings interface was viewed, or only a harmless cleanup occurred with no security change, this compound guidance does not apply.

## Abnormal reading
A service or persistence change alongside disabled protection or execution indicates a stronger abnormal pattern than the change alone.

## Severity
| Severity | When it applies |
|----------|-----------------|
| Low | not applicable on its own |
| Medium | A single service change with a plausible benign explanation. |
| High | An unexplained service or persistence change. |
| Critical | Persistence creation combined with disabled protection or suspicious execution. |

## Expected indicators
- service_configuration_changed
- scheduled_task_created
- startup_item_added
- defender_disabled
- script_execution

## False-positive checks
- If only a settings interface was viewed, or only a harmless cleanup occurred with no security change, this compound record does not apply.
- Do not combine a routine service view with unrelated context to force critical severity.

## Evidence combinations
Each added severe signal raises severity toward critical.

## Analyst notes
- Judge only on evidence present in the structured input; absent evidence is not positive evidence.
- Visibility is not execution; an opened interface is not a change; a restored setting does not erase the original change.
- Do not use scenario or category identifiers to decide the classification.

## Examples
- Benign: Only Services is viewed with no change, so this guidance does not apply.
- Abnormal: A service start type is changed while Defender is disabled and a script is executed.

## Related records
PERSIST_002, SEC_003, PROC_005
