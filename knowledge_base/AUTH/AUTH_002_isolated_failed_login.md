# Isolated Failed Login

**ID:** AUTH_002 | **Category:** AUTH | **Type:** contrastive diagnostic guidance

<!-- Document ID: AUTH_002 -->

## Summary
Explains that a single or very limited failed login is usually ordinary user error.

## Observable conditions
- `failed_login_activity = true`
- `failed_login_count_band` indicates a single or very low count
- no other risky evidence is present

## Normal / benign reading
One isolated failed login, or a very small number immediately followed by success, is consistent with ordinary mistyping and is usually normal or low risk.

## Abnormal reading
Concern increases when failures are repeated, occur at high frequency, or are combined with other risky evidence.

## Severity
| Severity | When it applies |
|----------|-----------------|
| Low | A single isolated failed login with no other risk signal. |
| Medium | A limited number of repeated failures may reach medium under the repeated-failure guidance. |
| High | not applicable on its own |
| Critical | not from this record alone; needs a compound signal |

## Expected indicators
- failed_login
- successful_login
- no_additional_risky_activity

## False-positive checks
- One isolated failed login is usually mistyping; do not escalate a single failure to risky.
- A failure immediately followed by success is normal user error, not an attack.

## Evidence combinations
One failure plus success stays low. Rising count or additional risk signals escalate under other AUTH documents.

## Analyst notes
- Judge only on evidence present in the structured input; absent evidence is not positive evidence.
- Visibility is not execution; an opened interface is not a change; a restored setting does not erase the original change.
- Do not use scenario or category identifiers to decide the classification.

## Examples
- Benign: One failed login is recorded, immediately followed by a successful login.
- Abnormal: A single failure is only the start of a larger burst of failures; the repeated-failure guidance then applies.

## Related records
AUTH_001, AUTH_003, AUTH_004
