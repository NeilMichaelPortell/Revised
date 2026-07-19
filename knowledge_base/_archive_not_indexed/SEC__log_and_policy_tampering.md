# Log And Policy Tampering

Category: SEC

## Description
Log and policy tampering includes event log clearing, stopping security services, and changing controls that preserve audit evidence.

## Risk interpretation
These actions are often defense evasion and should be treated as high or critical risk.

## Expected indicators
- event_log_clearing
- security_service_stopped
- defense_evasion

## Example scenarios
- `wevtutil.exe` clears Windows event logs.
- `sc.exe` stops a security-related service.
- Policy or audit settings are weakened after suspicious activity.
