# Network Settings Viewed Only

**ID:** NET_003 | **Category:** NET | **Type:** benign baseline guidance

<!-- Document ID: NET_003 -->

## Summary
Explains that viewing network settings without change is normal.

## Observable conditions
- `viewed_interface = network_settings`
- no configuration change is recorded

## Normal / benign reading
Opening network settings to view the profile or connection details is normal and does not change configuration.

## Abnormal reading
This becomes relevant only if a network configuration is actually changed, or if scanning is executed.

## Severity
| Severity | When it applies |
|----------|-----------------|
| Low | Network settings are viewed with no change. |
| Medium | not applicable on its own |
| High | Applies only when a change or scan is present. |
| Critical | not from this record alone; needs a compound signal |

## Expected indicators
- network_profile_viewed
- network_profile_unchanged
- settings_viewed
- no_additional_risky_activity

## False-positive checks
- Viewing network settings is not changing them; require a recorded change or a scan before escalating.
- Do not treat an opened network-settings interface as reconfiguration.

## Evidence combinations
Viewing plus no change stays low. A change or scan moves to the relevant NET guidance.

## Analyst notes
- Judge only on evidence present in the structured input; absent evidence is not positive evidence.
- Visibility is not execution; an opened interface is not a change; a restored setting does not erase the original change.
- Do not use scenario or category identifiers to decide the classification.

## Examples
- Benign: Network settings are opened and the profile is viewed with no change.
- Abnormal: Network settings are opened and a scanner is then used to execute a scan.

## Related records
NET_001, NET_004, NORMAL_004
