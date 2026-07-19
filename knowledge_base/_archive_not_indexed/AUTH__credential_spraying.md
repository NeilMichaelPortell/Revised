# Credential Spraying

Category: AUTH

## Description
Credential spraying uses a small number of common passwords across many accounts to avoid simple lockout controls.

## Risk interpretation
Large numbers of failed logins across accounts should be treated as high or critical risk because one successful attempt can expose many systems.

## Expected indicators
- password_spray
- many_failed_logins
- authentication_anomaly

## Example scenarios
- Dozens of failed logins appear across several users.
- Login attempts come from a new device or public network profile.
- A burst of failures is followed by a suspicious success.
