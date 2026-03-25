Create a well-structured GitHub Issue for PuzzlePod.

Using the product-manager skill from `skills/product-manager.md`:

1. Ask for: title, description, type (bug/feature/task/spike), priority, component
2. Search for duplicates: `gh issue list --search "$ARGUMENTS"`
3. Create the issue with Goal + Acceptance Criteria format:

```
## Goal

<one-line goal statement>

## Acceptance Criteria

- [ ] <criterion 1>
- [ ] <criterion 2>
```

4. Apply labels: type label (bug/enhancement/task/spike), priority label (P0-P3), component label (comp:puzzled, comp:puzzlectl, etc.)
5. Link to milestone if applicable
6. Use: `gh issue create --title "..." --body "..." --label "..." --milestone "..."`
