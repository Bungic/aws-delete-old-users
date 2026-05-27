"""
IAM user lifecycle automation.

Stages (state stored as IAM tags on the user):
    1. WARN       last_used > 180 days, no WarnedAt tag       email + WarnedAt tag
    2. DEACTIVATE WarnedAt > 7 days                            disable login + keys, DeactivatedAt tag
    3. DELETE     DeactivatedAt > 30 days                      delete user

Reconciliation runs first each invocation: if a user has come back
(last_used moved past WarnedAt, or they were re-enabled manually),
the relevant stage tag is cleared and the cycle resets.

Users tagged LifecyclePolicy=exempt are skipped entirely.
"""

import csv
import io
import logging
import os
import time
from datetime import datetime, timezone
from typing import Optional

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

iam = boto3.client("iam")
sns = boto3.client("sns")

INACTIVITY_DAYS = int(os.environ.get("INACTIVITY_DAYS", "180"))
WARN_GRACE_DAYS = int(os.environ.get("WARN_GRACE_DAYS", "7"))
DEACTIVATE_GRACE_DAYS = int(os.environ.get("DEACTIVATE_GRACE_DAYS", "30"))

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"

TAG_WARNED_AT = "WarnedAt"
TAG_DEACTIVATED_AT = "DeactivatedAt"
TAG_EXEMPT = "LifecyclePolicy"


def lambda_handler(event, context):
    if DRY_RUN:
        logger.info("starting run in DRY_RUN mode, no mutations will be made")

    summary = {
        "scanned": 0, "warned": 0, "deactivated": 0,
        "deleted": 0, "reconciled": 0, "skipped": 0, "errors": 0,
    }

    try:
        report = fetch_credential_report()
    except ClientError as e:
        logger.error("failed to fetch credential report: %s", e)
        raise

    now = datetime.now(timezone.utc)

    for row in report:
        username = row.get("user", "")
        if not username or username == "<root_account>":
            continue

        summary["scanned"] += 1
        try:
            outcome = process_user(username, row, now)
            if outcome:
                summary[outcome] = summary.get(outcome, 0) + 1
        except Exception as e:
            logger.exception("could not process user %s: %s", username, e)
            summary["errors"] += 1

    logger.info(
        "run complete: scanned=%d warned=%d deactivated=%d deleted=%d "
        "reconciled=%d skipped=%d errors=%d",
        summary["scanned"], summary["warned"], summary["deactivated"],
        summary["deleted"], summary["reconciled"], summary["skipped"],
        summary["errors"],
    )
    return summary


def process_user(username: str, row: dict, now: datetime) -> Optional[str]:
    try:
        tags = get_user_tags(username)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            logger.info("user %s no longer exists, skipping", username)
            return "skipped"
        raise

    if tags.get(TAG_EXEMPT) == "exempt":
        return "skipped"

    last_used = compute_last_used(row)
    cleared = reconcile(username, tags, last_used, now)
    for key in cleared:
        tags.pop(key, None)

    deactivated_at = parse_tag_date(tags.get(TAG_DEACTIVATED_AT))
    if deactivated_at:
        if (now - deactivated_at).days >= DEACTIVATE_GRACE_DAYS:
            delete_user(username)
            return "deleted"
        return "reconciled" if cleared else None

    warned_at = parse_tag_date(tags.get(TAG_WARNED_AT))
    if warned_at:
        if (now - warned_at).days >= WARN_GRACE_DAYS:
            deactivate_user(username, now)
            return "deactivated"
        return "reconciled" if cleared else None

    days_inactive = (now - last_used).days if last_used else None
    if days_inactive is not None and days_inactive >= INACTIVITY_DAYS:
        warn_user(username, days_inactive, now)
        return "warned"

    return "reconciled" if cleared else None


def reconcile(username: str, tags: dict, last_used: Optional[datetime],
              now: datetime) -> set:
    """Clear stage tags if the user has effectively returned to active use.

    Returns the set of tag keys that were cleared, so the caller can
    update its in-memory view without re-fetching (also keeps DRY_RUN honest).
    """
    cleared = set()

    warned_at = parse_tag_date(tags.get(TAG_WARNED_AT))
    if warned_at and last_used and last_used > warned_at:
        logger.info("user %s used after warning, clearing %s",
                    username, TAG_WARNED_AT)
        if not DRY_RUN:
            iam.untag_user(UserName=username, TagKeys=[TAG_WARNED_AT])
        cleared.add(TAG_WARNED_AT)

    deactivated_at = parse_tag_date(tags.get(TAG_DEACTIVATED_AT))
    if deactivated_at and is_user_active(username):
        logger.info("user %s appears re-enabled, clearing %s",
                    username, TAG_DEACTIVATED_AT)
        if not DRY_RUN:
            iam.untag_user(UserName=username, TagKeys=[TAG_DEACTIVATED_AT])
        cleared.add(TAG_DEACTIVATED_AT)

    return cleared


def warn_user(username: str, days_inactive: int, now: datetime):
    logger.info("user %s inactive %d days, sending warning",
                username, days_inactive)
    if DRY_RUN:
        return

    # Tag first so a notification failure does not cause a duplicate warn
    # on the next run. If the notification fails, the cycle still proceeds
    # correctly; only the human-visible alert is missed (logged loudly).
    iam.tag_user(UserName=username, Tags=[
        {"Key": TAG_WARNED_AT, "Value": now.strftime("%Y-%m-%d")}
    ])
    notify(
        action="warn",
        username=username,
        detail=(f"User {username} has been inactive for {days_inactive} days. "
                f"It will be deactivated in {WARN_GRACE_DAYS} days unless used."),
    )


def deactivate_user(username: str, now: datetime):
    logger.info("user %s deactivating", username)
    if DRY_RUN:
        return

    try:
        iam.delete_login_profile(UserName=username)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise

    keys_disabled = 0
    for key in paginate(iam, "list_access_keys", "AccessKeyMetadata", UserName=username):
        if key["Status"] == "Active":
            iam.update_access_key(
                UserName=username,
                AccessKeyId=key["AccessKeyId"],
                Status="Inactive",
            )
            keys_disabled += 1

    iam.tag_user(UserName=username, Tags=[
        {"Key": TAG_DEACTIVATED_AT, "Value": now.strftime("%Y-%m-%d")}
    ])
    notify(
        action="deactivate",
        username=username,
        detail=(f"User {username} deactivated. Login disabled, "
                f"{keys_disabled} access key(s) marked Inactive. "
                f"Will be deleted in {DEACTIVATE_GRACE_DAYS} days."),
    )
    logger.info("user %s deactivated, keys_disabled=%d", username, keys_disabled)


def delete_user(username: str):
    logger.info("user %s deleting", username)
    if DRY_RUN:
        return

    cleanup_login_profile(username)
    cleanup_access_keys(username)
    cleanup_signing_certificates(username)
    cleanup_ssh_keys(username)
    cleanup_service_specific_credentials(username)
    cleanup_attached_policies(username)
    cleanup_inline_policies(username)
    cleanup_groups(username)
    cleanup_permissions_boundary(username)
    cleanup_mfa_devices(username)

    iam.delete_user(UserName=username)
    notify(
        action="delete",
        username=username,
        detail=f"User {username} has been deleted.",
    )
    logger.info("user %s deleted", username)


def cleanup_login_profile(username: str):
    try:
        iam.delete_login_profile(UserName=username)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise


def cleanup_access_keys(username: str):
    for key in paginate(iam, "list_access_keys", "AccessKeyMetadata", UserName=username):
        iam.delete_access_key(UserName=username, AccessKeyId=key["AccessKeyId"])


def cleanup_signing_certificates(username: str):
    for cert in paginate(iam, "list_signing_certificates", "Certificates", UserName=username):
        iam.delete_signing_certificate(
            UserName=username, CertificateId=cert["CertificateId"])


def cleanup_ssh_keys(username: str):
    for key in paginate(iam, "list_ssh_public_keys", "SSHPublicKeys", UserName=username):
        iam.delete_ssh_public_key(
            UserName=username, SSHPublicKeyId=key["SSHPublicKeyId"])


def cleanup_service_specific_credentials(username: str):
    resp = iam.list_service_specific_credentials(UserName=username)
    for cred in resp.get("ServiceSpecificCredentials", []):
        iam.delete_service_specific_credential(
            UserName=username,
            ServiceSpecificCredentialId=cred["ServiceSpecificCredentialId"],
        )


def cleanup_attached_policies(username: str):
    for policy in paginate(iam, "list_attached_user_policies", "AttachedPolicies", UserName=username):
        iam.detach_user_policy(UserName=username, PolicyArn=policy["PolicyArn"])


def cleanup_inline_policies(username: str):
    for name in paginate(iam, "list_user_policies", "PolicyNames", UserName=username):
        iam.delete_user_policy(UserName=username, PolicyName=name)


def cleanup_groups(username: str):
    for group in paginate(iam, "list_groups_for_user", "Groups", UserName=username):
        iam.remove_user_from_group(
            UserName=username, GroupName=group["GroupName"])


def cleanup_permissions_boundary(username: str):
    try:
        iam.delete_user_permissions_boundary(UserName=username)
    except ClientError as e:
        # NoSuchEntity is returned when the user has no boundary attached.
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise


def cleanup_mfa_devices(username: str):
    for device in paginate(iam, "list_mfa_devices", "MFADevices", UserName=username):
        serial = device["SerialNumber"]
        iam.deactivate_mfa_device(UserName=username, SerialNumber=serial)
        if serial.startswith("arn:"):
            try:
                iam.delete_virtual_mfa_device(SerialNumber=serial)
            except ClientError as e:
                logger.warning("could not delete virtual MFA %s: %s", serial, e)


def fetch_credential_report() -> list:
    """Generate (if needed) and parse the IAM credential report."""
    deadline = time.time() + 60
    while True:
        resp = iam.generate_credential_report()
        if resp["State"] == "COMPLETE":
            break
        if time.time() > deadline:
            raise RuntimeError("credential report generation timed out")
        time.sleep(2)

    csv_bytes = iam.get_credential_report()["Content"]
    reader = csv.DictReader(io.StringIO(csv_bytes.decode("utf-8")))
    return list(reader)


def compute_last_used(row: dict) -> Optional[datetime]:
    """Most recent activity across password and access keys.

    Falls back to user_creation_time if the account was never used,
    so brand-new-but-forgotten accounts age into the policy correctly.
    """
    candidates = [
        row.get("password_last_used"),
        row.get("access_key_1_last_used_date"),
        row.get("access_key_2_last_used_date"),
    ]
    parsed = [parse_iso(v) for v in candidates]
    parsed = [p for p in parsed if p is not None]
    if parsed:
        return max(parsed)

    return parse_iso(row.get("user_creation_time"))


def get_user_tags(username: str) -> dict:
    tags = {}
    for tag in paginate(iam, "list_user_tags", "Tags", UserName=username):
        tags[tag["Key"]] = tag["Value"]
    return tags


def is_user_active(username: str) -> bool:
    try:
        iam.get_login_profile(UserName=username)
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise

    for key in paginate(iam, "list_access_keys", "AccessKeyMetadata", UserName=username):
        if key["Status"] == "Active":
            return True
    return False


def notify(action: str, username: str, detail: str):
    if not SNS_TOPIC_ARN:
        logger.debug("SNS_TOPIC_ARN not set, skipping notification for %s", username)
        return
    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"IAM lifecycle: {action} {username}"[:100],
            Message=detail,
        )
    except ClientError as e:
        # Swallow so the lifecycle proceeds, but log loudly so a CloudWatch
        # metric filter on "NOTIFY_FAILED" can alert operators.
        logger.error("NOTIFY_FAILED action=%s user=%s error=%s",
                     action, username, e)


def paginate(client, op_name: str, key: str, **kwargs):
    """Yield items from a paginated list_* IAM call."""
    paginator = client.get_paginator(op_name)
    for page in paginator.paginate(**kwargs):
        for item in page.get(key, []):
            yield item


def parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value or value in ("N/A", "no_information", "not_supported"):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def parse_tag_date(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
