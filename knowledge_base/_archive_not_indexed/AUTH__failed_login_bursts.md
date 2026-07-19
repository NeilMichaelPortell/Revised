# Failed Login Bursts

Category: AUTH

## Description
Failed login bursts occur when one account receives several unsuccessful authentication attempts in a short period.

## Risk interpretation
Several failures can indicate password guessing, account lockout attempts, or a compromised credential workflow. Risk is higher for privileged accounts or off-hours activity.

## Expected indicators
- multiple_failed_logins
- single_account_attack
- authentication_anomaly

## Example scenarios
- Eight failed login attempts target one user.
- Several failed attempts are followed by a successful privileged login.
- Failed logins occur outside the user's normal work pattern.
