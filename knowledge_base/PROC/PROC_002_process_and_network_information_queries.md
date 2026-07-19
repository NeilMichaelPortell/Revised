# Process and Network Information Queries

**ID:** PROC_002 | **Category:** PROC | **Type:** contrastive diagnostic guidance

<!-- Document ID: PROC_002 -->

## Summary
Explains that enumerating processes or querying network configuration can be benign administrative activity.

## Observable conditions
- a command listed running processes or queried network configuration
- no execution of downloaded or unknown code is present

## Normal / benign reading
Listing running processes or checking network configuration is common in troubleshooting and administration and is usually benign on its own.

## Abnormal reading
These queries are more concerning when part of a broader unusual command sequence, or combined with security weakening or unknown-code execution.

## Severity
| Severity | When it applies |
|----------|-----------------|
| Low | A single informational query with no other risk signal. |
| Medium | Repeated enumeration forming an unusual pattern. |
| High | Enumeration combined with script execution or security weakening. |
| Critical | Only as part of a broader compound pattern. |

## Expected indicators
- process_enumeration
- network_configuration_query
- basic_command_use
- terminal_activity
- no_additional_risky_activity

## False-positive checks
- Listing processes or querying network configuration is common troubleshooting; a single informational query is not an attack.
- Escalate only when enumeration forms part of a broader unusual sequence or co-occurs with security weakening.

## Evidence combinations
A lone query is low. Enumeration plus execution or security weakening raises severity.

## Analyst notes
- Judge only on evidence present in the structured input; absent evidence is not positive evidence.
- Visibility is not execution; an opened interface is not a change; a restored setting does not erase the original change.
- Do not use scenario or category identifiers to decide the classification.

## Examples
- Benign: A single command lists running processes during troubleshooting.
- Abnormal: Repeated enumeration is followed by script execution and disabled protection.

## Related records
PROC_001, PROC_003, PROC_004
