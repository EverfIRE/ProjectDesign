# Project Design Keeper 1.1.1

Fixes valid multi-file knowledge-pack updates failing during apply with `Apply candidate validation work exceeds the limit of 250000 items`, despite passing preview. This affects both Easy and normal mode.

Apply verifies the candidate before staging and before every output mutation. These repeated checks previously spent one shared single-pass resource budget. Each pass now retains its own input and source-read limits; aggregate validation work is bounded by the authenticated output count plus two passes. Each pass retains its existing deadline, and the complete validation sequence is bounded to at most five minutes.

All automatic validation, source freshness checks, ownership checks, authorization, and transactional rollback remain enabled. Easy mode still skips only human confirmation. No user settings migration is required.

Regression coverage includes a valid update with 40 outputs, 99 records, and 1002 source fingerprints, per-pass work and analysis limits, and rollback after the total validation deadline expires.

After installing 1.1.1, reload the plugin or restart its MCP process. Regenerate the preview for any failed 1.1.0 changeset, then apply the newly generated changeset.
