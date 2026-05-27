# Changelog

## [0.1.0] - 2026-05-20

Initial public release.

- Three-stage IAM user lifecycle: warn (180 days idle), deactivate (7 days after warn), delete (30 days after deactivate).
- State stored as tags on the IAM user (`WarnedAt`, `DeactivatedAt`). No external database.
- Reconciliation pass on every run: returning users clear their stage tags automatically.
- Exempt break-glass accounts with `LifecyclePolicy=exempt`.
- SNS notifications for every lifecycle event. Empty `SNS_TOPIC_ARN` falls back to log-only.
- Dry-run mode via `DRY_RUN=true`.
- Tag-before-notify ordering so a failed notification does not cause a duplicate warn on the next run.
- 17 unit tests using `moto` (no real AWS calls).
