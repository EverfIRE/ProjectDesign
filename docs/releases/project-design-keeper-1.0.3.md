# Project Design Keeper 1.0.3

- Tag: `project-design-keeper-v1.0.3`
- Assets: `project-design-keeper-1.0.3.zip` and `SHA256SUMS.txt`

This patch addresses oversized apply-approval forms. The previous form expanded
every affected path and record ID as formatted JSON, putting the confirmation
instructions after the entire list. A 39-file changeset could crowd out the
input controls in the host dialog.

The form now uses at most eight logical lines and 1,536 UTF-8 bytes, with file
and record counts, the changeset ID, full digest, and expiry. The confirmation
code appears first and in the labelled input field. Long project paths are
explicitly shortened for display. Review the complete file list and diff from
`preview_update` before approving.

Authorization still binds the complete changeset and requires an exact typed
confirmation. Declines, cancellations, expiry, tampering, and stale changesets
continue to fail without applying changes.

Regression coverage includes a real 39-file preview/approval/apply round trip,
all 39 output files, and bounded display for long Unicode paths and large record
lists. Actual dialog layout remains host-dependent and needs verification after
updating the installed plugin to 1.0.3 and starting a new task.

Validation: 1,065 tests passed with 15 platform skips. The initial full run's
installation-suite repository-stability check detected a concurrent documentation
edit; all 68 installation tests and their stability check passed on a separate
rerun with files held stable. Type checking, relocated runtime smoke, exact
25-file package verification, and all 20 distribution checks also passed.
