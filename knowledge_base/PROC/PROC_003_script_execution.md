# Script Execution

**ID:** PROC_003 | **Category:** PROC | **Type:** abnormal single-signal guidance

<!-- Document ID: PROC_003 -->

## Summary
Explains interpretation of executing a script.

## Observable conditions
- `verified_activity_context.command_activity` or `verified_activity_context.verified_commands` indicate a script was executed
- or `verified_activity_context.script_name` is present with execution

## Normal / benign reading
A sanctioned administrative or deployment script may be legitimate, but legitimacy should be supported by context rather than assumed from the mere fact of execution.

## Abnormal reading
Executing a script, particularly one that is unknown, follows a download, or accompanies security weakening, is a confirmed risky action.

## Severity
| Severity | When it applies |
|----------|-----------------|
| Low | not applicable on its own |
| Medium | A single script execution with a plausible benign context and no other risk signal. |
| High | Script execution that is unknown, follows a download, or accompanies another risk signal. |
| Critical | Script execution combined with disabled protection, persistence creation, or unknown removable media. |

## Expected indicators
- script_execution
- powershell_activity
- terminal_activity
- suspicious_command_pattern
- file_download

## False-positive checks
- A sanctioned deployment or administrative script may be legitimate; require context, not just the fact of execution, before assuming malice.
- Do not treat script execution as critical on its own without a compounding signal.

## Evidence combinations
Execution alone is medium to high by context. With disabled protection or persistence it approaches critical.

## Analyst notes
- Judge only on evidence present in the structured input; absent evidence is not positive evidence.
- Visibility is not execution; an opened interface is not a change; a restored setting does not erase the original change.
- Do not use scenario or category identifiers to decide the classification.

## Examples
- Benign: A documented deployment script is executed in a sanctioned process with supporting context.
- Abnormal: A script is executed immediately after a download with no sanctioned explanation.

## Related records
PROC_001, PROC_004, PROC_005
