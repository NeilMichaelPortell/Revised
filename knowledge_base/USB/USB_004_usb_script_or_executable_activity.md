# USB Script or Executable Activity

**ID:** USB_004 | **Category:** USB | **Type:** abnormal single-signal guidance

<!-- Document ID: USB_004 -->

## Summary
Covers access to or execution of scripts and executables from removable media.

## Observable conditions
- `verified_activity_context.usb_content_type` indicates a script or executable
- a script or executable on the device is accessed or executed

## Normal / benign reading
Mere presence of a script or executable file on a drive is not execution. An authorised software installer accessed in a sanctioned process may be legitimate, but this should be supported by evidence rather than assumed.

## Abnormal reading
Accessing or executing a script or executable from a removable device, especially an unknown one, is a confirmed risky action.

## Severity
| Severity | When it applies |
|----------|-----------------|
| Low | not applicable on its own |
| Medium | A script or executable is present but only viewed. |
| High | A script or executable from the device is accessed or executed. |
| Critical | Execution from an unknown device combined with disabled protection or another severe signal. |

## Expected indicators
- usb_script_or_executable_accessed
- usb_script_or_executable_present
- executable_execution
- script_execution
- unknown_usb
- unknown_executable

## False-positive checks
- Presence of a script or executable on a drive is not execution; require access/execution evidence.
- A signed installer accessed in a sanctioned process may be legitimate; do not assume malice from file type alone.

## Evidence combinations
Presence only is medium. Access or execution is high. Add disabled protection for critical.

## Analyst notes
- Judge only on evidence present in the structured input; absent evidence is not positive evidence.
- Visibility is not execution; an opened interface is not a change; a restored setting does not erase the original change.
- Do not use scenario or category identifiers to decide the classification.

## Examples
- Benign: A signed installer on an authorised device is present but not executed.
- Abnormal: An executable on an unknown device is executed.

## Related records
USB_002, USB_003, USB_005
