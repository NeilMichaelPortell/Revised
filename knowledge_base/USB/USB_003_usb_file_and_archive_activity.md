# USB File and Archive Activity

**ID:** USB_003 | **Category:** USB | **Type:** contrastive diagnostic guidance

<!-- Document ID: USB_003 -->

## Summary
Covers file copying and archive access on removable media.

## Observable conditions
- `usb_connection_count` is one or more
- `verified_activity_context.archive_accessed = true` or a file was copied to or from the device

## Normal / benign reading
Copying an ordinary document or opening a normal archive on an authorised device is routine.

## Abnormal reading
Archive access on an unknown device, or archive access alongside script or executable presence, is more concerning because archives can conceal executable content.

## Severity
| Severity | When it applies |
|----------|-----------------|
| Low | A normal document is copied on an authorised device. |
| Medium | An archive is accessed on an unknown device with no execution. |
| High | An archive is accessed and a script or executable from it is accessed or executed. |
| Critical | Only with additional severe signals. |

## Expected indicators
- usb_archive_accessed
- usb_file_copied
- usb_script_or_executable_present
- authorised_usb
- unknown_usb
- no_file_execution

## False-positive checks
- Opening a normal archive on an authorised device is routine; escalate only when the device is unknown or execution follows.
- Archive access is not the same as running content from the archive.

## Evidence combinations
Authorised plus normal copy is low. Unknown plus archive plus executable presence trends high.

## Analyst notes
- Judge only on evidence present in the structured input; absent evidence is not positive evidence.
- Visibility is not execution; an opened interface is not a change; a restored setting does not erase the original change.
- Do not use scenario or category identifiers to decide the classification.

## Examples
- Benign: A document is copied from an authorised USB drive.
- Abnormal: An archive on an unknown device is accessed and an executable inside it is accessed.

## Related records
USB_001, USB_002, USB_004
