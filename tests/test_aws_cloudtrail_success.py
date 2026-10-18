"""Behavioral regression checks for the two AWS IAM Sigma rules.

Uses pySigma's parsed conditions and a small, explicit predicate evaluator.
This does not execute SPL or emulate a SIEM's ingestion/normalization.
"""
import json
import os
import re
import unittest
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionOR,
    ConditionNOT,
    ConditionFieldEqualsValueExpression,
)
from sigma.types import SigmaExists, SigmaString

ROOT = Path(os.environ.get("AWS_DETECTION_REPO", Path(__file__).resolve().parents[1]))
FIXTURES = Path(__file__).parent / "fixtures" / "aws_cloudtrail_success.json"
RULE_NAMES = (
    "aws_iam_access_key_created.yml",
    "aws_iam_privilege_escalation.yml",
)


def matches(condition, event):
    """Evaluate only the condition types used here; fail on unsupported types."""
    if isinstance(condition, ConditionAND):
        return all(matches(arg, event) for arg in condition.args)
    if isinstance(condition, ConditionOR):
        return any(matches(arg, event) for arg in condition.args)
    if isinstance(condition, ConditionNOT):
        return not matches(condition.args[0], event)
    if isinstance(condition, ConditionFieldEqualsValueExpression):
        value = condition.value
        if isinstance(value, SigmaExists):
            return (condition.field in event) == value.exists
        if isinstance(value, SigmaString):
            observed = event.get(condition.field)
            return observed is not None and re.fullmatch(
                str(value.to_regex().regexp), str(observed), re.IGNORECASE | re.DOTALL
            ) is not None
    raise TypeError(f"Unsupported condition in fixture evaluator: {condition!r}")


class CloudTrailSuccessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = {
            name: SigmaCollection.from_yaml(
                (ROOT / "cloud" / "aws-identity" / name).read_text()
            ).rules[0]
            for name in RULE_NAMES
        }

    def rule_matches(self, name, event):
        return any(
            matches(condition.parsed, event)
            for condition in self.rules[name].detection.parsed_condition
        )

    def test_cloudtrail_event_fixtures(self):
        for fixture in json.loads(FIXTURES.read_text()):
            for rule_name in RULE_NAMES:
                with self.subTest(case=fixture["case"], rule=rule_name):
                    self.assertEqual(
                        self.rule_matches(rule_name, fixture["event"]),
                        rule_name in fixture["matches"],
                    )

    def test_each_policy_operation_preserves_success_and_failure_behavior(self):
        rule_name = "aws_iam_privilege_escalation.yml"
        for operation in (
            "PutUserPolicy", "AttachUserPolicy", "PutRolePolicy",
            "AttachRolePolicy", "CreatePolicy", "PutGroupPolicy", "AttachGroupPolicy",
        ):
            event = {"eventSource": "iam.amazonaws.com", "eventName": operation}
            with self.subTest(operation=operation, outcome="success"):
                self.assertTrue(self.rule_matches(rule_name, event))
            with self.subTest(operation=operation, outcome="denied"):
                self.assertFalse(self.rule_matches(
                    rule_name, {**event, "errorCode": "AccessDenied"}
                ))


if __name__ == "__main__":
    unittest.main()
