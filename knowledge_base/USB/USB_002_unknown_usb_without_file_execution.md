# Unknown USB Without File Execution

**ID:** USB_002 | **Category:** USB | **Type:** contrastive diagnostic guidance

<!-- Document ID: USB_002 -->

## Summary
Distinguishes an unknown device connection from actual execution of content on it.

## Observable conditions
- `usb_connection_count` is one or more
- `verified_activity_context.device_trust` indicates an unknown or untrusted device
- `verified_activity_context.usb_files_browsed` may be true, but no execution is present

## Normal / benign reading
An unknown device that is connected and whose files are only viewed is a limited concern; visibility is not execution.

## Abnormal reading
An unknown device raises concern above an authorised one, and concern increases further if a script or executable on it is accessed or executed, or if it repeats.

## Severity
| Severity | When it applies |
|----------|-----------------|
| Low | Not typical for an unknown device; usually at least medium. |
| Medium | An unknown device is connected and files are only viewed. |
| High | An unknown device where a script or executable is accessed. |
| Critical | Only with additional severe signals such as disabled protection alongside execution. |

## Expected indicators
- unknown_usb
- usb_connected
- usb_files_viewed
- usb_script_or_executable_present
- no_file_execution
- multiple_usb_connections

## False-positive checks
- An unknown device whose files are only browsed is a limited concern; visibility is not execution.
- Do not assume execution because a script or executable is present on the device.

## Evidence combinations
Unknown plus view-only is medium. Unknown plus accessed executable is high. Add security weakening for critical.

## Analyst notes
- Judge only on evidence present in the structured input; absent evidence is not positive evidence.
- Visibility is not execution; an opened interface is not a change; a restored setting does not erase the original change.
- Do not use scenario or category identifiers to decide the classification.

## Examples
- Benign: An unknown device is connected and its folders are viewed, with no file executed.
- Abnormal: An unknown device is connected and an executable file on it is accessed.

## Related records
USB_001, USB_003, USB_004
