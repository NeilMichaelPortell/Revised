# High-Frequency Failed Logins

**ID:** AUTH_004 | **Category:** AUTH | **Type:** abnormal single-signal guidance

<!-- Document ID: AUTH_004 -->

## Summary
Explains interpretation of a high failed-login count band.

## Observable conditions
- `failed_login_activity = true`
- `failed_login_count_band` indicates a high count

## Normal / benign reading
Even a high count can occasionally reflect a misconfigured client repeatedly retrying, but this is the less likely explanation and should not be assumed without support.

## Abnormal reading
A high number of failed logins, particularly within a short activity window, is a strong abnormal authentication signal consistent with automated guessing behaviour.

## Severity
| Severity | When it applies |
|----------|-----------------|
| Low | not applicable on its own |
| Medium | A high count with a plausible benign explanation and no other risk signal. |
| High | A high count within a short window, or with any additional risk signal. |
| Critical | A high count combined with several other severe signals such as disabled protection and scanning. |

## Expected indicators
- high_failed_login_count
- repeated_failed_logins
- rapid_activity_window
- public_network

## False-positive checks
- A high count can rarely be a misconfigured client retrying; only treat as benign if evidence supports it, otherwise it is abnormal.
- Do not convert the high-count band into a specific fabricated number.

## Evidence combinations
High count plus rapid window is high. High count plus disabled protection or scanning approaches critical.

## Analyst notes
- Judge only on evidence present in the structured input; absent evidence is not positive evidence.
- Visibility is not execution; an opened interface is not a change; a restored setting does not erase the original change.
- Do not use scenario or category identifiers to decide the classification.

## Examples
- Benign: A high count is recorded but is later attributed to a documented client misconfiguration.
- Abnormal: A high count occurs within a short window with no benign explanation available in the evidence.

## Related records
AUTH_003, AUTH_005, GLOBAL_002
