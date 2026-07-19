# Multiple Security Control Changes

**ID:** SEC_005 | **Category:** SEC | **Type:** compound-risk guidance

<!-- Document ID: SEC_005 -->

## Summary
Explains why several security-control changes together raise severity toward critical.

## Observable conditions
- more than one security control changed, such as Defender and a firewall profile

## Normal / benign reading
If only one setting was viewed or a single reverted change occurred, this compound guidance does not apply.

## Abnormal reading
Multiple security-control changes together indicate a coordinated weakening of defences and are more severe than any single change.

## Severity
| Severity | When it applies |
|----------|-----------------|
| Low | not applicable on its own |
| Medium | not applicable on its own |
| High | Two related security-control changes with no further escalation. |
| Critical | Several security controls disabled or changed together, or combined with execution or persistence creation. |

## Expected indicators
- defender_disabled
- defender_configuration_changed
- firewall_configuration_changed
- security_setting_restored

## False-positive checks
- If only one setting was viewed or a single reverted change occurred, this compound record does not apply.
- Do not count a view-only event as one of the multiple changes.

## Evidence combinations
The number and severity of concurrent changes drive severity toward critical.

## Analyst notes
- Judge only on evidence present in the structured input; absent evidence is not positive evidence.
- Visibility is not execution; an opened interface is not a change; a restored setting does not erase the original change.
- Do not use scenario or category identifiers to decide the classification.

## Examples
- Benign: Only one setting is viewed with no change, so this guidance does not apply.
- Abnormal: Defender is disabled and a firewall profile is turned off in the same activity window.

## Related records
SEC_003, SEC_004, GLOBAL_002
