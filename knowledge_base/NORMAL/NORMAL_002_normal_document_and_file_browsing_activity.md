**ID:** NORMAL_002 | **Category:** NORMAL | **Type:** benign baseline guidance

<!-- Document ID: NORMAL_002 -->

## Summary
Clarifies that viewing folders, files, and documents is normal and is not equivalent to executing content.

## Observable conditions
- `apps_opened` shows document or file-browsing applications
- `file_downloaded = false` or a downloaded file was not executed
- no script or executable execution is present

## Normal / benign reading
Viewing local folders, opening documents, and reading files are normal actions. Visibility of a file is not the same as execution of that file.

## Abnormal reading
File activity becomes relevant only if an executable or script is actually executed, or if a downloaded file is run, which would be reflected by separate execution evidence.

## Severity
| Severity | When it applies |
|----------|-----------------|
| Low | Files or documents are viewed or edited with no execution evidence. |
| Medium | not applicable on its own |
| High | Applies only if separate execution evidence is present. |
| Critical | not from this record alone; needs a compound signal |

## Expected indicators
- document_activity
- file_browsing
- media_viewing
- no_file_execution
- no_additional_risky_activity

## False-positive checks
- Viewing or opening a file is not executing it; do not infer execution from visibility.
- Browsing folders and reading documents is routine and needs no indicator beyond document/file activity.

## Evidence combinations
Viewing plus no execution supports normal. Viewing plus confirmed execution shifts interpretation to the relevant process or executable document.

## Analyst notes
- Judge only on evidence present in the structured input; absent evidence is not positive evidence.
- Visibility is not execution; an opened interface is not a change; a restored setting does not erase the original change.
- Do not use scenario or category identifiers to decide the classification.

## Examples
- Benign: A user opens several documents and browses folders with no execution or download-run evidence.
- Abnormal: A file is viewed and then a separate field shows an executable was executed; the execution is the relevant signal.

## Related records
NORMAL_001, PROC_001, USB_002
