# Benign Command-Line Use

**ID:** PROC_001 | **Category:** PROC | **Type:** benign baseline guidance

<!-- Document ID: PROC_001 -->

## Summary
Establishes that opening a shell and running basic commands is not automatically abnormal.

## Observable conditions
- `running_monitored_processes` or `apps_opened` shows PowerShell, Command Prompt, or a terminal
- `verified_activity_context.command_activity` indicates basic use
- no script execution or suspicious pattern is present

## Normal / benign reading
Opening PowerShell, Command Prompt, or a terminal and running basic commands such as a directory listing or a system-information query is normal, especially for development or administration.

## Abnormal reading
Command-line use becomes relevant when a script is executed, when an unusual or encoded-looking command appears, or when it co-occurs with security weakening.

## Severity
| Severity | When it applies |
|----------|-----------------|
| Low | Basic, harmless command-line use with no risky co-signal. |
| Medium | not applicable on its own |
| High | Applies only when execution or a suspicious pattern appears. |
| Critical | not from this record alone; needs a compound signal |

## Expected indicators
- powershell_activity
- cmd_activity
- terminal_activity
- basic_command_use
- development_activity
- no_additional_risky_activity

## False-positive checks
- Opening PowerShell, Command Prompt, or a terminal is NOT automatically abnormal; it is routine for development and administration.
- Basic commands (directory listing, system-information query) are benign; require script execution or a suspicious pattern before escalating.

## Evidence combinations
Basic commands stay low. Script execution or suspicious patterns move to the relevant PROC document.

## Analyst notes
- Judge only on evidence present in the structured input; absent evidence is not positive evidence.
- Visibility is not execution; an opened interface is not a change; a restored setting does not erase the original change.
- Do not use scenario or category identifiers to decide the classification.

## Examples
- Benign: PowerShell is opened and a directory listing is run with no script execution.
- Abnormal: A terminal is opened and an encoded-looking command is executed; the suspicious-pattern guidance applies.

## Related records
PROC_002, PROC_003, NORMAL_001
