# Service Persistence

Category: PERSIST

## Description
Service persistence creates or modifies Windows services so code starts automatically or runs with elevated privileges.

## Risk interpretation
New services from user-controlled paths should be critical risk because they can survive reboot and run with high privileges.

## Expected indicators
- service_change
- user_directory_binary
- persistence

## Example scenarios
- `sc.exe` creates an auto-start service from a user directory.
- A service binary changes outside a maintenance window.
- A new service appears after suspicious process execution.
