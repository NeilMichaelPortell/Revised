# Network Scanner Version Check Versus Active Scan

**ID:** NET_004 | **Category:** NET | **Type:** contrastive diagnostic guidance

<!-- Document ID: NET_004 -->

## Summary
Distinguishes opening or version-checking a scanner from executing an actual scan.

## Observable conditions
- `verified_activity_context.scanner_tool` indicates a scanner was opened or checked
- `verified_activity_context.scan_target` indicates whether a scan executed

## Normal / benign reading
Opening a network scanner or checking its version is not the same as running a scan; presence or a version check is a limited concern.

## Abnormal reading
Executing a network scan is a confirmed risky action. Severity depends on the target and accompanying context.

## Severity
| Severity | When it applies |
|----------|-----------------|
| Low | Not typical; opening a scanner is usually at least medium. |
| Medium | A scanner is opened or version-checked but no scan executes. |
| High | A network scan is executed. |
| Critical | Scanning combined with public-network exposure and authentication anomalies or disabled protection. |

## Expected indicators
- network_scanner_activity
- network_scan
- authorised_local_target
- no_additional_risky_activity

## False-positive checks
- Opening a scanner or checking its version is NOT the same as running a scan; separate presence from execution.
- Escalate to high only when a scan is actually executed.

## Evidence combinations
Opening a scanner is medium. Executing a scan is high. Add public-network and failed-login context for critical.

## Analyst notes
- Judge only on evidence present in the structured input; absent evidence is not positive evidence.
- Visibility is not execution; an opened interface is not a change; a restored setting does not erase the original change.
- Do not use scenario or category identifiers to decide the classification.

## Examples
- Benign: A scanner application is opened and its version is checked, with no scan executed.
- Abnormal: A network scan is executed against a local target.

## Related records
NET_003, NET_005, GLOBAL_002
