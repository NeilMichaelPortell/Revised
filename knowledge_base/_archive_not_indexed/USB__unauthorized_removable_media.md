# Unauthorized Removable Media

Category: USB

## Description
Unauthorized removable media includes USB storage devices connected without business approval or outside expected operating hours.

## Risk interpretation
Unapproved USB storage should usually be risky because it can introduce malware or support data exfiltration.

## Expected indicators
- unauthorized_usb
- removable_media
- after_hours_activity

## Example scenarios
- A removable drive is connected after hours.
- A new USB storage device appears on a locked-down endpoint.
- Removable media is used without a matching approval record.
