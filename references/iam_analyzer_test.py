import pytest
from iam_analyzer import iam_analyzer  # adjust import to your actual module/function path


def test_full_wildcard_action_and_resource_flagged():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "FullAdminWildcard",
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            }
        ],
    }
    result = iam_analyzer(policy)
    assert result == {"FullAdminWildcard"}


def test_service_wildcard_in_action_list_flagged():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ServiceWildcardNoCondition",
                "Effect": "Allow",
                "Action": ["s3:*", "iam:PassRole"],
                "Resource": "*",
            }
        ],
    }
    result = iam_analyzer(policy)
    assert result == {"ServiceWildcardNoCondition"}


def test_narrow_action_specific_resource_not_flagged():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "NarrowActionSpecificResource",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::app-data-bucket/*",
            }
        ],
    }
    result = iam_analyzer(policy)
    assert result == set()


def test_wildcard_resource_with_real_condition_not_flagged():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "WildcardResourceButConditioned",
                "Effect": "Allow",
                "Action": "ec2:*",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"aws:RequestedRegion": "us-east-1"}
                },
            }
        ],
    }
    result = iam_analyzer(policy)
    assert result == set()


def test_empty_condition_block_still_flagged():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EmptyConditionBlock",
                "Effect": "Allow",
                "Action": "dynamodb:*",
                "Resource": "*",
                "Condition": {},
            }
        ],
    }
    result = iam_analyzer(policy)
    assert result == {"EmptyConditionBlock"}


def test_not_action_with_allow_flagged():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "NotActionAllowEverythingElse",
                "Effect": "Allow",
                "NotAction": "iam:*",
                "Resource": "*",
            }
        ],
    }
    result = iam_analyzer(policy)
    assert result == {"NotActionAllowEverythingElse"}


def test_deny_wildcard_not_flagged():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyWildcardShouldNotFlag",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
            }
        ],
    }
    result = iam_analyzer(policy)
    assert result == set()


def test_wildcard_action_narrow_resource_not_flagged():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "WildcardActionNarrowResource",
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "arn:aws:s3:::app-data-bucket/*",
            }
        ],
    }
    result = iam_analyzer(policy)
    assert result == set()