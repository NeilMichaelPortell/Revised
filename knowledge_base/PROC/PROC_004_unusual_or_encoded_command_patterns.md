# Unusual or Encoded Command Patterns

**ID:** PROC_004 | **Category:** PROC | **Type:** abnormal single-signal guidance

<!-- Document ID: PROC_004 -->

## Summary
Explains interpretation of unusual or encoded-looking command patterns.

## Observable conditions
- `verified_activity_context.verified_commands` show an unusual, obfuscated, or encoded-looking pattern

## Normal / benign reading
Some legitimate tooling uses long or unusual command lines, so an unusual appearance alone is weaker evidence than confirmed obfuscation; supporting context matters.

## Abnormal reading
An encoded or deliberately obfuscated command pattern is a strong abnormal indicator because obfuscation is commonly used to hide intent.

## Severity
| Severity | When it applies |
|----------|-----------------|
| Low | not applicable on its own |
| Medium | A mildly unusual command with a plausible benign explanation. |
| High | A clearly encoded or obfuscated command pattern. |
| Critical | An obfuscated pattern combined with security weakening or persistence creation. |

## Expected indicators
- suspicious_command_pattern
- powershell_activity
- script_execution
- terminal_activity

## False-positive checks
- Some legitimate tooling uses long command lines; an unusual appearance alone is weaker than confirmed obfuscation.
- Do not infer an encoded command unless the pattern is genuinely present in the evidence.

## Evidence combinations
A suspicious pattern alone is high. With disabled protection or persistence it approaches critical.

## Analyst notes
- Judge only on evidence present in the structured input; absent evidence is not positive evidence.
- Visibility is not execution; an opened interface is not a change; a restored setting does not erase the original change.
- Do not use scenario or category identifiers to decide the classification.

## Examples
- Benign: A long but documented tooling command is recorded with supporting context.
- Abnormal: An encoded command pattern is executed with no legitimate explanation available.

## Related records
PROC_003, PROC_005, GLOBAL_001
