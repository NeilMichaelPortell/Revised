# Scheduled Task Persistence

Category: PERSIST

## Description
Scheduled task persistence uses Windows tasks to relaunch commands, scripts, or binaries at logon or on a recurring schedule.

## Risk interpretation
New scheduled tasks should be investigated when they launch scripts, run from user directories, or lack a valid change record.

## Expected indicators
- scheduled_task_change
- persistence
- powershell_execution

## Example scenarios
- A new task launches PowerShell at logon.
- `schtasks.exe` creates a task from a standard user session.
- A task points to a downloaded or unsigned file.
