# Startup Item Added or Removed

**ID:** PERSIST_004 | **Category:** PERSIST | **Type:** contrastive diagnostic guidance

<!-- Document ID: PERSIST_004 -->

## Summary
Explains interpretation of adding or removing a startup item.

## Observable conditions
- `startup_item_change = true`
- `verified_activity_context.startup_action` indicates an add or remove

## Normal / benign reading
Removing a harmless startup item is cleanup. A sanctioned application legitimately configuring startup may be normal with supporting context.

## Abnormal reading
Adding an unexplained startup item is a persistence mechanism and is a risky action when unexplained.

## Severity
| Severity | When it applies |
|----------|-----------------|
| Low | A harmless startup item is removed as cleanup. |
| Medium | A documented startup item is added with plausible context. |
| High | An unexplained startup item is added. |
| Critical | A startup change combined with disabled protection or execution. |

## Expected indicators
- startup_item_added
- startup_item_removed
- startup_items_viewed
- cleanup_activity

## False-positive checks
- Removing a harmless startup item is cleanup; a sanctioned application configuring startup may be normal with context.
- Escalate only for an unexplained startup addition.

## Evidence combinations
Removal as cleanup is low. Unexplained addition is high. With disabled protection it approaches critical.

## Analyst notes
- Judge only on evidence present in the structured input; absent evidence is not positive evidence.
- Visibility is not execution; an opened interface is not a change; a restored setting does not erase the original change.
- Do not use scenario or category identifiers to decide the classification.

## Examples
- Benign: An old startup entry is removed during cleanup.
- Abnormal: An unexplained startup item is added with no sanctioned context.

## Related records
PERSIST_001, PERSIST_003, PERSIST_005
