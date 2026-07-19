# Suspicious PowerShell

Category: PROC

## Description
Suspicious PowerShell includes encoded commands, hidden execution, script download behavior, or unusual use from a standard user profile.

## Risk interpretation
PowerShell is legitimate but becomes risky when it is encoded, obfuscated, or paired with downloads and security changes.

## Expected indicators
- encoded_powershell
- powershell_execution
- script_execution

## Example scenarios
- An encoded PowerShell command runs from a user session.
- PowerShell launches after a USB connection.
- PowerShell modifies security settings or persistence locations.
