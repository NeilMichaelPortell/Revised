# Authorised USB Use

**ID:** USB_001 | **Category:** USB | **Type:** benign baseline guidance

<!-- Document ID: USB_001 -->

## Summary
Explains that use of an authorised removable device is normal.

## Observable conditions
- `usb_connection_count` is one or more
- `verified_activity_context.device_trust` indicates an authorised device
- no script or executable execution from the device is present

## Normal / benign reading
Connecting an authorised removable device and viewing or copying ordinary documents is normal workplace activity.

## Abnormal reading
USB activity becomes relevant when the device is unknown or untrusted, when a script or executable on it is accessed, or when it co-occurs with security weakening.

## Severity
| Severity | When it applies |
|----------|-----------------|
| Low | An authorised device is used for ordinary file activity. |
| Medium | not applicable on its own |
| High | Applies only if execution or another risky signal appears. |
| Critical | not from this record alone; needs a compound signal |

## Expected indicators
- authorised_usb
- usb_connected
- usb_files_viewed
- usb_file_copied
- no_file_execution

## False-positive checks
- An authorised device used for ordinary file activity is normal; the device being present is not itself an indicator.
- Copying a document is not executing content from the device.

## Evidence combinations
Authorised device plus document activity stays low. Unknown device or execution moves to other USB documents.

## Analyst notes
- Judge only on evidence present in the structured input; absent evidence is not positive evidence.
- Visibility is not execution; an opened interface is not a change; a restored setting does not erase the original change.
- Do not use scenario or category identifiers to decide the classification.

## Examples
- Benign: An authorised USB drive is connected and a document is copied from it with no execution.
- Abnormal: A device flagged as unknown is connected and a script on it is accessed; the unknown-device guidance applies.

## Related records
USB_002, USB_003, NORMAL_002
