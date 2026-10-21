# Indexer policy: public by default, private exceptions

New container templates use `STGUARD_SOURCE_POLICY=private_exclusions`. Maintain
only each Sonarr instance's private-indexer list. An identified Sonarr history
source is eligible for the public cleanup policy unless it matches an exception;
no public-indexer list is needed when adding or renaming public indexers.

This is an operator-selected policy, NOT a claim that the guard has independently
verified a tracker's privacy flag. A newly added private indexer must be listed
before relying on this mode. Include every private alias, including separately
named freeleech entries. Private comparisons ignore case and surrounding spaces;
different names/aliases are not inferred, wildcarded or followed automatically.
An empty private list protects no identified source by name.

Missing, empty/whitespace, malformed or conflicting source identity still blocks
assessment. The source must come from the exact Sonarr grab bound to the current
download and content. Unknown identity is different from an identified but
unlisted name: the latter is now public by policy. Manual additions without that
history, wrong clients/categories/endpoints, private matches, healthy media and
normal completed/stopped torrents remain protected by the existing checks.

For file configuration:

```json
"indexers": {
  "mode": "private_exclusions",
  "private": ["Private Source", "Private Source - Freeleech"]
}
```

The same classification is checked during assessment and routine authorization,
including final fresh checks before dispatch. Full source policy is bound into
the ownership fingerprint and grant scope; changing mode or lists invalidates
previous approval. Adding a private exception before sending blocks that action.
Policy changes do not enable any live gate or issue/renew a grant.

## Existing configurations and migration

- Existing files without `indexers.mode` retain `public_allowlist` behavior: only
  their explicit public names are eligible, and unlisted names remain protected.
- Old environment templates with public-indexer variables but no explicit source
  policy retain allowlist mode, even with the new worker.
- New templates explicitly select `private_exclusions` and omit public-list
  fields. An old persisted policy cannot silently change modes through an
  implicit default: set the new policy explicitly to acknowledge migration.
- `STGUARD_CONFIG_SOURCE=file` preserves the private file instead of interpreting
  template policy variables. Change the file deliberately when using that mode.
- New private-exception mode ignores any obsolete public list; a private match
  always wins. Invalid policy modes/lists fail closed.

Before live adoption, review the exact private exceptions for BOTH owners and
the updated code, retain the complete journal, and explicitly authorize the new
code/scope. Do not clear holds, remove private exceptions or reuse an old grant to
work around a refusal. Updating source/template/image alone is not activation.
