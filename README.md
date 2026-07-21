# aws-delete-old-users

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE) ![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white) ![AWS Lambda](https://img.shields.io/badge/AWS%20Lambda-FF9900?logo=awslambda&logoColor=white)

AWS Lambda that automatically warns, deactivates, and deletes inactive IAM users.

## Lifecycle

| Stage      | Trigger                                         | Action                                           |
|------------|-------------------------------------------------|--------------------------------------------------|
| Warn       | `last_used > 180 days` and no `WarnedAt` tag    | Publish warn event to SNS, set `WarnedAt=YYYY-MM-DD` tag |
| Deactivate | `WarnedAt > 7 days` ago                         | Disable login profile, mark all keys Inactive, set `DeactivatedAt` tag |
| Delete     | `DeactivatedAt > 30 days` ago                   | Full teardown, then delete: remove login profile, delete access keys, clear signing certificates / SSH keys / service-specific credentials, detach managed policies, delete inline policies, remove group memberships, delete permissions boundary, deactivate MFA, then `DeleteUser` |

State lives entirely on the IAM user as tags. No external database.

## Reconciliation

Each invocation, before evaluating, the Lambda checks whether a user has effectively returned:

- If `last_used > WarnedAt`, the warning tag is cleared.
- If a user has an active login profile or active access key while still tagged `DeactivatedAt`, that tag is cleared (someone re-enabled them manually).

This makes the script idempotent and tolerant of out-of-band manual changes.

## Exemptions

Tag a user with `LifecyclePolicy=exempt` to skip them entirely. Use for break-glass accounts and rarely-invoked service accounts.

## Configuration

All thresholds and addresses come from environment variables.

| Variable                | Default | Purpose                                                   |
|-------------------------|---------|-----------------------------------------------------------|
| `INACTIVITY_DAYS`       | `180`   | Days of inactivity before warning                         |
| `WARN_GRACE_DAYS`       | `7`     | Days between warning and deactivation                     |
| `DEACTIVATE_GRACE_DAYS` | `30`    | Days between deactivation and deletion                    |
| `SNS_TOPIC_ARN`         | (empty) | SNS topic to publish lifecycle events. If unset, events are logged only. |
| `DRY_RUN`               | `false` | Log intended actions without executing                    |

All warn / deactivate / delete events are published to the configured SNS topic. Subscribe email, Slack, or PagerDuty endpoints to that topic as needed.

## Deployment

```bash
zip function.zip lambda_function.py
aws lambda update-function-code \
  --function-name delete-old-users \
  --zip-file fileb://function.zip
```

Schedule with EventBridge: `rate(7 days)`.

Recommended Lambda settings:
- Runtime: `python3.12`
- Timeout: `300` seconds
- Memory: `256` MB
- Reserved concurrency: `1` (prevents overlapping runs)

Update `iam-policy.json` to point `sns:Publish` at the actual SNS topic ARN before applying.

## Operational alerts

Set a CloudWatch Logs metric filter on the pattern `NOTIFY_FAILED` and route it to an alarm. A failed notification does not stop the lifecycle, but operators should know when an inactive user was tagged without a corresponding alert reaching its owner.

## IAM permissions required

See `iam-policy.json`.

## Audit

Every action goes through CloudTrail (`UpdateAccessKey`, `DeleteLoginProfile`, `DeleteUser`, `TagUser`, `UntagUser`). No additional audit storage is needed.

## First-time rollout

1. Deploy with `DRY_RUN=true`.
2. Run weekly for 2 cycles, review CloudWatch logs for false positives.
3. Tag any unexpected hits with `LifecyclePolicy=exempt`.
4. Set `DRY_RUN=false`.

---

Part of my cloud-engineering portfolio → **[frkangungor.com](https://frkangungor.com)**
