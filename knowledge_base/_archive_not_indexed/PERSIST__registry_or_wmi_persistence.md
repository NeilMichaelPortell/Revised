# Registry Or WMI Persistence

Category: PERSIST

## Description
Registry and WMI persistence use configuration changes such as Run keys or WMI subscriptions to relaunch code.

## Risk interpretation
These changes should be high or critical risk when they involve scripts, user directories, or stealthy event subscriptions.

## Expected indicators
- registry_run_key
- wmi_subscription
- stealthy_configuration_change

## Example scenarios
- A Run key is modified to launch a PowerShell script.
- A WMI event subscription starts a user process.
- Persistence appears after a downloaded file is executed.
