"""
Unit tests for lambda_function.

Run with: pytest tests/

Tests use moto to mock IAM/SNS. No real AWS calls are made.
"""

import os
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

os.environ["SNS_TOPIC_ARN"] = ""

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import boto3
from moto import mock_aws

import lambda_function as lf


NOW = datetime(2026, 5, 4, tzinfo=timezone.utc)


@pytest.fixture
def aws():
    with mock_aws():
        iam = boto3.client("iam", region_name="us-east-1")
        sns = boto3.client("sns", region_name="us-east-1")
        lf.iam = iam
        lf.sns = sns
        lf.SNS_TOPIC_ARN = ""
        lf.DRY_RUN = False
        # moto does not implement these IAM endpoints
        with patch.object(lf, "cleanup_service_specific_credentials"), \
             patch.object(lf, "cleanup_permissions_boundary"):
            yield iam


def make_user(iam, name, tags=None, with_login=True):
    iam.create_user(
        UserName=name,
        Tags=[{"Key": k, "Value": v} for k, v in (tags or {}).items()],
    )
    if with_login:
        iam.create_login_profile(UserName=name, Password="TempPass1!@#$")


def credential_row(user, last_used=None, created=None):
    return {
        "user": user,
        "password_last_used": last_used or "N/A",
        "access_key_1_last_used_date": "N/A",
        "access_key_2_last_used_date": "N/A",
        "user_creation_time": created or "2020-01-01T00:00:00+00:00",
    }


def test_active_user_no_action(aws):
    make_user(aws, "alice")
    row = credential_row("alice", last_used=(NOW - timedelta(days=10)).isoformat())

    assert lf.process_user("alice", row, NOW) is None
    assert "WarnedAt" not in lf.get_user_tags("alice")


def test_inactive_user_gets_warned(aws):
    make_user(aws, "bob")
    row = credential_row("bob", last_used=(NOW - timedelta(days=200)).isoformat())

    assert lf.process_user("bob", row, NOW) == "warned"
    assert lf.get_user_tags("bob")["WarnedAt"] == "2026-05-04"


def test_warned_user_after_grace_gets_deactivated(aws):
    make_user(aws, "carol", tags={"WarnedAt": "2026-04-20"})
    aws.create_access_key(UserName="carol")

    row = credential_row("carol", last_used="2025-10-01T00:00:00+00:00")
    assert lf.process_user("carol", row, NOW) == "deactivated"

    tags = lf.get_user_tags("carol")
    assert "DeactivatedAt" in tags
    assert "WarnedAt" in tags
    keys = aws.list_access_keys(UserName="carol")["AccessKeyMetadata"]
    assert all(k["Status"] == "Inactive" for k in keys)


def test_warned_user_within_grace_no_action(aws):
    make_user(aws, "carla", tags={"WarnedAt": "2026-05-01"})
    row = credential_row("carla", last_used="2025-10-01T00:00:00+00:00")

    assert lf.process_user("carla", row, NOW) is None
    assert "DeactivatedAt" not in lf.get_user_tags("carla")


def test_deactivated_user_after_grace_gets_deleted(aws):
    make_user(aws, "dave", tags={"DeactivatedAt": "2026-03-01"}, with_login=False)
    row = credential_row("dave", last_used="2025-08-01T00:00:00+00:00")

    assert lf.process_user("dave", row, NOW) == "deleted"
    with pytest.raises(aws.exceptions.NoSuchEntityException):
        aws.get_user(UserName="dave")


def test_warned_user_returns_clears_tag(aws):
    make_user(aws, "eve", tags={"WarnedAt": "2026-05-01"})
    row = credential_row("eve", last_used=(NOW - timedelta(days=1)).isoformat())

    assert lf.process_user("eve", row, NOW) == "reconciled"
    assert "WarnedAt" not in lf.get_user_tags("eve")


def test_exempt_user_skipped(aws):
    make_user(aws, "frank", tags={"LifecyclePolicy": "exempt"})
    row = credential_row("frank", last_used="2024-01-01T00:00:00+00:00")

    assert lf.process_user("frank", row, NOW) == "skipped"
    assert "WarnedAt" not in lf.get_user_tags("frank")


def test_deactivated_user_reenabled_resets_cycle(aws):
    """When an admin re-enables a deactivated user, the cycle resets.
    If they're still inactive, they'll be warned again next cycle."""
    make_user(aws, "grace", tags={"DeactivatedAt": "2026-04-30"})
    row = credential_row("grace", last_used="2025-08-01T00:00:00+00:00")

    lf.process_user("grace", row, NOW)

    tags = lf.get_user_tags("grace")
    assert "DeactivatedAt" not in tags
    assert "WarnedAt" in tags


def test_never_used_account_uses_creation_time(aws):
    make_user(aws, "henry", with_login=False)
    row = credential_row("henry", last_used="N/A", created="2020-01-01T00:00:00+00:00")

    assert lf.process_user("henry", row, NOW) == "warned"


def test_user_with_attached_and_inline_policies_is_deletable(aws):
    make_user(aws, "ivan", tags={"DeactivatedAt": "2026-03-01"}, with_login=False)
    key = aws.create_access_key(UserName="ivan")["AccessKey"]
    aws.update_access_key(UserName="ivan", AccessKeyId=key["AccessKeyId"], Status="Inactive")
    aws.put_user_policy(
        UserName="ivan", PolicyName="inline-test",
        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:Get*","Resource":"*"}]}',
    )
    aws.create_group(GroupName="dev")
    aws.add_user_to_group(GroupName="dev", UserName="ivan")

    row = credential_row("ivan", last_used="2025-08-01T00:00:00+00:00")
    assert lf.process_user("ivan", row, NOW) == "deleted"

    with pytest.raises(aws.exceptions.NoSuchEntityException):
        aws.get_user(UserName="ivan")


def test_dry_run_makes_no_changes(aws):
    lf.DRY_RUN = True
    try:
        make_user(aws, "jane")
        row = credential_row("jane", last_used=(NOW - timedelta(days=200)).isoformat())

        assert lf.process_user("jane", row, NOW) == "warned"
        assert "WarnedAt" not in lf.get_user_tags("jane")
    finally:
        lf.DRY_RUN = False


def test_dry_run_reconcile_simulates_correctly(aws):
    """In DRY_RUN, after reconcile clears WarnedAt in memory, evaluation
    should proceed as if the tag is gone (i.e. re-warn if still inactive)."""
    lf.DRY_RUN = True
    try:
        make_user(aws, "kate", tags={"WarnedAt": "2026-05-01"})
        # last_used is AFTER WarnedAt, so reconcile should clear it,
        # but in DRY_RUN no real untag happens. Local state should still
        # behave as if cleared.
        row = credential_row("kate", last_used="2026-05-03T00:00:00+00:00")

        result = lf.process_user("kate", row, NOW)
        # cleared but user is fresh now (1 day inactive), no warn
        assert result == "reconciled"
        # real tag still there because DRY_RUN
        assert "WarnedAt" in lf.get_user_tags("kate")
    finally:
        lf.DRY_RUN = False


def test_handler_continues_after_per_user_error(aws):
    """If process_user raises for one user, the handler continues with the rest."""
    make_user(aws, "leo")
    make_user(aws, "mary")

    row_leo = credential_row("leo", last_used=(NOW - timedelta(days=10)).isoformat())
    row_mary = credential_row("mary", last_used=(NOW - timedelta(days=10)).isoformat())

    original_process = lf.process_user

    def selective(username, row, now):
        if username == "leo":
            raise RuntimeError("simulated processing error")
        return original_process(username, row, now)

    with patch.object(lf, "fetch_credential_report",
                      return_value=[row_leo, row_mary]), \
         patch.object(lf, "process_user", side_effect=selective):
        result = lf.lambda_handler({}, None)

    assert result["scanned"] == 2
    assert result["errors"] == 1


def test_root_account_skipped(aws):
    row = credential_row("<root_account>", last_used="2020-01-01T00:00:00+00:00")
    with patch.object(lf, "fetch_credential_report", return_value=[row]):
        result = lf.lambda_handler({}, None)
    assert result["scanned"] == 0


def test_user_deleted_between_report_and_processing(aws):
    """If a user vanished between the credential report and processing,
    we should skip rather than error."""
    row = credential_row("ghost", last_used="2025-01-01T00:00:00+00:00")
    assert lf.process_user("ghost", row, NOW) == "skipped"


def test_warn_tags_before_notify(aws):
    """Tag must be set before notification so a notify failure does not
    cause a duplicate warn on the next run."""
    make_user(aws, "nora")
    row = credential_row("nora", last_used=(NOW - timedelta(days=200)).isoformat())

    call_order = []

    original_tag_user = aws.tag_user
    def tracking_tag_user(**kwargs):
        call_order.append("tag")
        return original_tag_user(**kwargs)

    def tracking_notify(**kwargs):
        call_order.append("notify")

    with patch.object(lf.iam, "tag_user", side_effect=tracking_tag_user), \
         patch.object(lf, "notify", side_effect=tracking_notify):
        lf.process_user("nora", row, NOW)

    assert call_order == ["tag", "notify"]


def test_compute_last_used_uses_max(aws):
    row = {
        "user": "x",
        "password_last_used": "2025-01-01T00:00:00+00:00",
        "access_key_1_last_used_date": "2026-04-01T00:00:00+00:00",
        "access_key_2_last_used_date": "2025-06-01T00:00:00+00:00",
        "user_creation_time": "2020-01-01T00:00:00+00:00",
    }
    result = lf.compute_last_used(row)
    assert result == datetime(2026, 4, 1, tzinfo=timezone.utc)
