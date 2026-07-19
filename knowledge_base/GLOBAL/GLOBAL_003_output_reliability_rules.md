# Output Reliability Rules

Document ID: GLOBAL_003
Category: GLOBAL
Document type: global output-reliability rules
Version: 1.0

## Purpose

Reinforces the required output format. These rules do not change the task or
the schema; they only remind the model to produce a well-formed response.

## Rules

- Return exactly one classification from the permitted classification values.
- Return exactly one risk level from the permitted risk values.
- Use indicator tokens only from the controlled indicator vocabulary.
- Return one valid JSON object and no prose outside it.
- Do not return placeholder values such as `normal or risky`,
  `low, medium, high, or critical`, `unknown classification`, or `depends`.
- Do not include scenario identifiers, categories, or answer-key information.

## Interpretation constraints

- These reliability rules are supplied identically in both the baseline and the
  knowledge-augmented conditions, so they do not advantage either condition.
