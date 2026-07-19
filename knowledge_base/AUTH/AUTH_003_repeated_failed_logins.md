# Repeated Failed Logins

**ID:** AUTH_003 | **Category:** AUTH | **Type:** contrastive diagnostic guidance

<!-- Document ID: AUTH_003 -->

## Summary
Explains how repeated failed logins raise concern above an isolated error.

## Observable conditions
- `failed_login_activity = true`
- `failed_login_count_band` indicates multiple failures

## Normal / benign reading
A limited number of repeated failures can still be human error, for example a forgotten password before a supported reset, especially when followed by a normal successful login.

## Abnormal reading
Repeated failures become abnormal when they are numerous, occur within a short activity window, or are combined with a public network profile or other risky evidence.

## Severity
| Severity | When it applies |
|----------|-----------------|
| Low | A very small number of failures immediately resolved. |
| Medium | Multiple repeated failures with no other risk signal. |
| High | Repeated failures combined with another risk signal such as a public network profile or a suspicious success pattern. |
| Critical | Only when combined with several other severe signals; not from failed logins alone. |

## Expected indicators
- repeated_failed_logins
- rapid_activity_window
- public_network
- successful_login

## False-positive checks
- A small number of failures before a supported reset can be human error; weigh the count band, not the mere presence of failures.
- Do not invent an exact count when only a qualitative band is provided.

## Evidence combinations
Repeated failures alone are medium. With public network or rapid repetition they move toward high.

## Analyst notes
- Judge only on evidence present in the structured input; absent evidence is not positive evidence.
- Visibility is not execution; an opened interface is not a change; a restored setting does not erase the original change.
- Do not use scenario or category identifiers to decide the classification.

## Examples
- Benign: A few failed attempts occur before a supported password reset and a normal successful login.
- Abnormal: Many failures occur in a short window on a public network profile before a success.

## Related records
AUTH_002, AUTH_004, AUTH_005
