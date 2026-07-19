# Routine Desktop and Application Activity

**ID:** NORMAL_001 | **Category:** NORMAL | **Type:** benign baseline guidance

<!-- Document ID: NORMAL_001 -->

## Summary
Describes ordinary desktop application use so that everyday productivity activity is not mistaken for a security event.

## Observable conditions
- `apps_opened` lists standard desktop or productivity applications
- `risky_processes` is empty
- `failed_login_activity = false`
- no security-control, persistence, or USB change is present

## Normal / benign reading
Opening standard applications such as an editor, a browser, a communication tool, or a document viewer is normal desktop activity. Development work using an editor and its integrated terminal is also normal when there is no script execution, security-control change, or suspicious command pattern.

## Abnormal reading
Ordinary application use becomes relevant only if it co-occurs with independent risky evidence such as disabled protection, script execution, or an unknown removable device. The application activity itself is not the abnormal signal in that case.

## Severity
| Severity | When it applies |
|----------|-----------------|
| Low | All observed activity is routine application or document use with no risky co-signals. |
| Medium | not applicable on its own |
| High | not applicable on its own |
| Critical | not from this record alone; needs a compound signal |

## Expected indicators
- normal_app_activity
- document_activity
- communication_app_activity
- development_activity
- media_viewing
- no_additional_risky_activity

## False-positive checks
- Do not flag an editor, browser, or terminal being open as risky on its own.
- A development environment (editor + integrated PowerShell/Python) is normal; require an independent risky signal before escalating.

## Evidence combinations
Routine application use combined with no security, persistence, authentication, or USB signals supports a normal, low-risk interpretation. Only independent risky signals change this.

## Analyst notes
- Judge only on evidence present in the structured input; absent evidence is not positive evidence.
- Visibility is not execution; an opened interface is not a change; a restored setting does not erase the original change.
- Do not use scenario or category identifiers to decide the classification.

## Examples
- Benign: A device shows an editor and a browser opened, an empty risky-process list, and no failed-login activity.
- Abnormal: An editor is open, but the same summary also shows Defender disabled; here the abnormal signal is the disabled protection, not the editor.

## Related records
NORMAL_002, NORMAL_003, PROC_001
