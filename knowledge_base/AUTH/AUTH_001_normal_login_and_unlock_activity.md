# Normal Login and Unlock Activity

**ID:** AUTH_001 | **Category:** AUTH | **Type:** benign baseline guidance

<!-- Document ID: AUTH_001 -->

## Summary
Establishes that successful logins and screen unlocks are normal authentication events.

## Observable conditions
- `failed_login_activity = false`
- a successful login or unlock occurred

## Normal / benign reading
A successful login or a normal screen lock and unlock cycle is expected authentication activity and is normal.

## Abnormal reading
Authentication becomes relevant when repeated or high-frequency failed logins occur, or when failures accompany other risky evidence.

## Severity
| Severity | When it applies |
|----------|-----------------|
| Low | Successful login or normal lock and unlock with no failed attempts. |
| Medium | not applicable on its own |
| High | not applicable on its own |
| Critical | not from this record alone; needs a compound signal |

## Expected indicators
- successful_login
- screen_lock_activity
- no_additional_risky_activity

## False-positive checks
- A successful login or a lock/unlock cycle is expected; do not treat it as an indicator.
- Do not escalate on authentication activity unless failed logins are present.

## Evidence combinations
Successful login with no failures stays low. Failures move interpretation to the repeated or high-frequency guidance.

## Analyst notes
- Judge only on evidence present in the structured input; absent evidence is not positive evidence.
- Visibility is not execution; an opened interface is not a change; a restored setting does not erase the original change.
- Do not use scenario or category identifiers to decide the classification.

## Examples
- Benign: A user logs in successfully and unlocks the device with no failed attempts recorded.
- Abnormal: A successful login follows a burst of failed attempts; the repeated-failure guidance then applies.

## Related records
AUTH_002, AUTH_003, NORMAL_001
