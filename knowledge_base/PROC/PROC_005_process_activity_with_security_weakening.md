# Process Activity With Security Weakening

**ID:** PROC_005 | **Category:** PROC | **Type:** compound-risk guidance

<!-- Document ID: PROC_005 -->

## Summary
Explains how process activity combines with security weakening to raise severity.

## Observable conditions
- script execution or a suspicious command pattern is present
- an independent security signal is present, such as disabled protection

## Normal / benign reading
If only basic commands were used with no genuine security change, this compound guidance does not apply.

## Abnormal reading
Script execution or suspicious command patterns alongside disabled protection or security-control changes indicate a stronger abnormal pattern than either signal alone.

## Severity
| Severity | When it applies |
|----------|-----------------|
| Low | not applicable on its own |
| Medium | Basic commands plus one limited additional context. |
| High | Script execution alongside one security signal. |
| Critical | Suspicious execution combined with disabled protection and persistence creation. |

## Expected indicators
- script_execution
- suspicious_command_pattern
- powershell_activity
- defender_disabled
- scheduled_task_created

## False-positive checks
- If only basic commands were used with no genuine security change, this compound record does not apply.
- Do not pair benign command use with unrelated context to inflate severity.

## Evidence combinations
Each added severe signal raises severity toward critical.

## Analyst notes
- Judge only on evidence present in the structured input; absent evidence is not positive evidence.
- Visibility is not execution; an opened interface is not a change; a restored setting does not erase the original change.
- Do not use scenario or category identifiers to decide the classification.

## Examples
- Benign: Only a directory listing is run while protection remains enabled, so this guidance does not apply.
- Abnormal: An encoded command executes while Defender is disabled and a scheduled task is created.

## Related records
PROC_003, PROC_004, SEC_003
