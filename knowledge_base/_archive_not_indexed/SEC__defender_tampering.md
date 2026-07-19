# Defender Tampering

Category: SEC

## Description
Defender tampering includes disabling endpoint protection, changing antivirus exclusions, or weakening malware prevention controls.

## Risk interpretation
Security control tampering should usually be high or critical risk because it can enable later malicious activity and reduce detection.

## Expected indicators
- defender_disabled
- av_exclusion
- security_control_tampering

## Example scenarios
- Microsoft Defender is disabled using PowerShell.
- An antivirus exclusion is added for the downloads folder.
- Protection settings change without an approved maintenance window.
