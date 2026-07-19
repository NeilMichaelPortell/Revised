# Defender Disabled

**ID:** SEC_003 | **Category:** SEC | **Type:** abnormal single-signal guidance

<!-- Document ID: SEC_003 -->

## Summary
Explains interpretation of disabled Microsoft Defender real-time protection.

## Observable conditions
- `defender_disabled = true`, or `defender.realtime_protection_enabled = false`

## Normal / benign reading
There are rare sanctioned reasons to disable protection temporarily, but this should be supported by explicit evidence and not assumed; by default disabling protection is abnormal.

## Abnormal reading
Disabling Defender real-time protection removes a key defence layer and is a confirmed high-risk security action.

## Severity
| Severity | When it applies |
|----------|-----------------|
| Low | not applicable on its own |
| Medium | not applicable on its own |
| High | Defender real-time protection is disabled. |
| Critical | Disabled protection combined with execution, persistence creation, or additional security-control changes. |

## Expected indicators
- defender_disabled
- defender_configuration_changed

## False-positive checks
- A rare sanctioned disable may exist, but require explicit supporting evidence; by default disabled protection is high risk.
- Do not assume a benign reason for disabled protection without evidence.

## Evidence combinations
Disabled protection alone is high. Combined with execution or persistence it approaches critical.

## Analyst notes
- Judge only on evidence present in the structured input; absent evidence is not positive evidence.
- Visibility is not execution; an opened interface is not a change; a restored setting does not erase the original change.
- Do not use scenario or category identifiers to decide the classification.

## Examples
- Benign: A sanctioned maintenance window explicitly documents a temporary disable; evidence must support this.
- Abnormal: Defender real-time protection is disabled with no supporting sanctioned context.

## Related records
SEC_002, SEC_004, SEC_005
