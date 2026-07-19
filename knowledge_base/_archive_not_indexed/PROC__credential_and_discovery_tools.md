# Credential And Discovery Tools

Category: PROC

## Description
Credential and discovery tools include binaries that dump credentials, scan networks, or enumerate internal resources.

## Risk interpretation
These tools should be high or critical risk when they appear on standard user endpoints without a valid administrative reason.

## Expected indicators
- credential_dumping
- network_scanner
- reconnaissance

## Example scenarios
- `mimikatz.exe` or `procdump.exe` appears in a user profile.
- `nmap.exe` runs from a non-admin workstation.
- A user endpoint performs broad internal discovery.
