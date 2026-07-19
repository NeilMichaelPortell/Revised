# Unusual Success After Failures

Category: AUTH

## Description
This pattern combines repeated failed authentication attempts with a later successful login, especially on a privileged or unusual account.

## Risk interpretation
The successful login may represent credential compromise. It should be reviewed as high risk when paired with admin privileges, a new device, or public network activity.

## Expected indicators
- failed_then_success
- privileged_account
- off_hours_login

## Example scenarios
- A privileged account succeeds after six failures.
- A login succeeds from a device that has no previous history.
- Authentication attempts occur late at night or from an unusual network.
