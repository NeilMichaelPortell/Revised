# Evidence and Non-Inference Rules

Document ID: GLOBAL_001
Category: GLOBAL
Document type: global evidence rules
Version: 1.0

## Purpose

Defines the evidence boundary for all classification. These rules apply to
every scenario and constrain how the structured input may be interpreted.

## Rules

- Classify using only evidence present in the structured input.
- Missing evidence must not be treated as positive evidence.
- Values of zero, false, none, or an empty list mean the signal was not
  observed, not that a risky action was hidden.
- Qualitative count bands must not be converted into invented exact numbers.
- Visibility of a file does not imply execution of that file.
- Presence of a tool does not imply malicious use of that tool.
- A public network profile alone does not imply abnormal behaviour.
- Viewing a settings interface does not imply changing a setting.
- Restoring a changed setting does not erase that the change occurred.
- Removing a harmless test artefact is cleanup, not persistence creation.
- Multiple independent risky signals may justify higher severity than any one
  signal alone.
- Choose expected indicators only from the controlled indicator vocabulary.
- Do not mention scenario identifiers, categories, or any answer-key
  information in the output.

## Interpretation constraints

- These rules take precedence when a category document appears to conflict.
- When evidence is ambiguous, prefer the more cautious benign interpretation
  unless a confirmed risky action is present.
