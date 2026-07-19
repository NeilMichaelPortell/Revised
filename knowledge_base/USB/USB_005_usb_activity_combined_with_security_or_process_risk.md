# USB Activity Combined With Security or Process Risk

**ID:** USB_005 | **Category:** USB | **Type:** compound-risk guidance

<!-- Document ID: USB_005 -->

## Summary
Explains how USB activity combines with security weakening or suspicious process activity to raise severity.

## Observable conditions
- USB activity is present
- an independent risky signal is present, such as disabled protection or script execution

## Normal / benign reading
If the USB activity is authorised and there is no genuine additional risk signal, this compound guidance does not apply.

## Abnormal reading
USB activity alongside disabled protection, suspicious command patterns, or script execution indicates a stronger abnormal pattern than USB activity alone.

## Severity
| Severity | When it applies |
|----------|-----------------|
| Low | not applicable on its own |
| Medium | Authorised USB plus one limited additional context. |
| High | Unknown USB with execution, or USB activity with disabled protection. |
| Critical | Execution from an unknown device combined with disabled protection or security-control changes. |

## Expected indicators
- unknown_usb
- usb_script_or_executable_accessed
- defender_disabled
- suspicious_command_pattern
- script_execution
- executable_execution

## False-positive checks
- If the USB activity is authorised and there is no genuine additional risk signal, this compound record does not apply.
- Do not combine an authorised-device event with unrelated benign context to force a higher severity.

## Evidence combinations
Each added severe signal raises severity; the combination justifies high or critical.

## Analyst notes
- Judge only on evidence present in the structured input; absent evidence is not positive evidence.
- Visibility is not execution; an opened interface is not a change; a restored setting does not erase the original change.
- Do not use scenario or category identifiers to decide the classification.

## Examples
- Benign: An authorised USB is used while Defender remains enabled and no script runs, so this guidance does not apply.
- Abnormal: An executable on an unknown USB is executed while Defender is disabled.

## Related records
USB_004, SEC_003, PROC_005
