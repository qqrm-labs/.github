"""Exercise the exact inline policy shipped to reusable-workflow callers."""

import io
import json
import os
from pathlib import Path
import tempfile
import textwrap
import types
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/security.yml"
SOURCE = WORKFLOW.read_text().split("# BEGIN CODEQL MODE POLICY\n", 1)[1]
SOURCE = textwrap.dedent(SOURCE.split("# END CODEQL MODE POLICY", 1)[0])
POLICY = types.ModuleType("codeql_policy_under_test")
exec(compile(SOURCE, str(WORKFLOW), "exec"), POLICY.__dict__)

SHA = "a" * 40
CONTEXT = {
    "GITHUB_REPOSITORY": "example/project",
    "GITHUB_EVENT_NAME": "pull_request",
    "GITHUB_REF": "refs/pull/7/merge",
    "GITHUB_REF_PROTECTED": "false",
    "DEFAULT_BRANCH": "main",
    "PR_HEAD_REPOSITORY": "example/project",
    "PR_BASE_REF": "main",
    "CODEQL_HEAD_SHA": SHA,
}
NATIVE = {"id": 42, "path": POLICY.NATIVE_PATH, "state": "active"}
RUN = {
    "id": 123, "path": POLICY.NATIVE_PATH, "head_sha": SHA,
    "status": "completed", "conclusion": "success",
    "html_url": "https://github.com/example/project/actions/runs/123",
}
JOBS = [{"name": f"Analyze ({language})", "status": "completed", "conclusion": "success"}
        for language in ("rust", "actions")]


class CodeQLPolicyTests(unittest.TestCase):
    def test_only_explicit_private_unavailability_is_accepted(self):
        self.assertEqual(POLICY.validate_mode("advanced", "false", "rust"), ["rust"])
        self.assertEqual(POLICY.validate_mode("default", "false", "rust, actions"), ["rust", "actions"])
        self.assertEqual(POLICY.validate_mode("unavailable", "true", "rust"), ["rust"])
        for mode in ("", "disabled", "Default", "typo"):
            with self.subTest(mode=mode), self.assertRaises(RuntimeError):
                POLICY.validate_mode(mode, "true", "rust")
        for private in ("false", "", "True", "1"):
            with self.subTest(private=private), self.assertRaises(RuntimeError):
                POLICY.validate_mode("unavailable", private, "rust")
        for languages in ("", "rust,", "rust,rust", "rust,unknown language"):
            with self.subTest(languages=languages), self.assertRaises(RuntimeError):
                POLICY.validate_mode("default", "false", languages)

    def test_default_trigger_scope_is_explicit(self):
        cases = [
            ("pull_request", "refs/pull/7/merge", "false", True),
            ("push", "refs/heads/main", "false", True),
            ("push", "refs/heads/release", "true", True),
            ("push", "refs/heads/feature", "false", False),
            ("push", "refs/tags/v1", "true", False),
            ("workflow_dispatch", "refs/heads/main", "false", True),
            ("workflow_dispatch", "refs/heads/feature", "false", False),
            ("schedule", "refs/heads/main", "false", True),
        ]
        for event, ref, protected, expected in cases:
            with self.subTest(event=event, ref=ref):
                self.assertEqual(POLICY.current_scan_required(
                    event, ref, "main", protected, "example/project", "example/project", "main"), expected)
        for event, branch, protected in (("workflow_run", "main", "false"),
                                         ("push", "", "false"), ("push", "main", "")):
            with self.subTest(event=event, branch=branch), self.assertRaises(RuntimeError):
                POLICY.current_scan_required(event, "refs/heads/main", branch, protected, "example/project")

    def test_fork_and_stacked_pr_scope_uses_the_actual_base_branch(self):
        # The target can itself be a fork: same-repository PRs still qualify.
        self.assertTrue(POLICY.current_scan_required(
            "pull_request", "refs/pull/7/merge", "main", "false", "fork-owner/project", "fork-owner/project", "main"))
        with patch.object(POLICY, "get_json") as api:
            self.assertFalse(POLICY.current_scan_required(
                "pull_request", "refs/pull/7/merge", "main", "false", "example/project", "contributor/project", "main"))
            api.assert_not_called()
        for protected in (False, True):
            with self.subTest(protected=protected), patch.object(POLICY, "get_json", return_value={"protected": protected}) as api:
                self.assertEqual(POLICY.current_scan_required(
                    "pull_request", "refs/pull/7/merge", "main", "false", "example/project", "example/project", "release/v2"), protected)
                api.assert_called_once_with("/repos/example/project/branches/release%2Fv2")
        with patch.object(POLICY, "get_json", return_value={}), self.assertRaises(RuntimeError):
            POLICY.current_scan_required(
                "pull_request", "refs/pull/7/merge", "main", "false", "example/project", "example/project", "release/v2")
        with self.assertRaises(RuntimeError):
            POLICY.current_scan_required("pull_request", "refs/pull/7/merge", "main", "false", "example/project")

    def test_native_failure_or_missing_language_cannot_pass(self):
        POLICY.require_analysis_jobs(RUN, JOBS, ["rust", "actions"])
        for conclusion in ("failure", "cancelled", "skipped", "neutral", None):
            with self.subTest(run=conclusion), self.assertRaises(RuntimeError):
                POLICY.require_analysis_jobs(dict(RUN, conclusion=conclusion), JOBS, ["rust"])
        cases = [JOBS[:1], [], JOBS + JOBS[:1], [JOBS[0], dict(JOBS[1], status="in_progress")]]
        cases += [[JOBS[0], dict(JOBS[1], conclusion=value)]
                  for value in ("failure", "skipped", "neutral", None)]
        for jobs in cases:
            with self.subTest(jobs=jobs), self.assertRaises(RuntimeError):
                POLICY.require_analysis_jobs(RUN, jobs, ["rust", "actions"])

    def check_default(self, workflows=None, runs=None, jobs=None, context=None):
        fixtures = {"workflows": [NATIVE] if workflows is None else workflows,
                    "workflow_runs": [RUN] if runs is None else runs,
                    "jobs": JOBS if jobs is None else jobs}
        with patch.dict(os.environ, CONTEXT | (context or {}), clear=True), \
                patch.object(POLICY, "records", side_effect=lambda path, key: fixtures[key]) as records, \
                patch.object(POLICY.time, "monotonic", side_effect=[0, 721]), \
                patch.object(POLICY.time, "sleep") as sleep:
            result = POLICY.verify_default(["rust", "actions"])
            sleep.assert_not_called()
            return result, records.call_args_list

    def test_active_native_workflow_and_exact_head_are_required(self):
        result, calls = self.check_default()
        self.assertIn(SHA, result)
        self.assertIn("separate CodeQL result check", result)
        self.assertIn("does not assert", result)
        self.assertTrue(any("head_sha=" + SHA in call.args[0] for call in calls))
        cases = [
            {"workflows": []},
            {"workflows": [dict(NATIVE, state="disabled_manually")]},
            {"workflows": [dict(NATIVE, path=".github/workflows/codeql.yml")]},
            {"runs": []},
            {"runs": [dict(RUN, head_sha="b" * 40)]},
            {"runs": [dict(RUN, path=".github/workflows/codeql.yml")]},
            {"runs": [RUN, dict(RUN, id=124, conclusion="failure")]},
            {"jobs": JOBS[:1]},
            {"context": {"CODEQL_HEAD_SHA": ""}},
        ]
        for case in cases:
            with self.subTest(case=case), self.assertRaises(RuntimeError):
                self.check_default(**case)

    def test_out_of_scope_push_is_not_reported_as_a_scan(self):
        result, calls = self.check_default(context={"GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/feature"})
        self.assertIn("no CodeQL analysis is claimed", result)
        self.assertEqual(len(calls), 1)
        with self.assertRaises(RuntimeError):
            self.check_default(workflows=[], context={"GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/feature"})

    def test_waits_for_the_independent_native_run(self):
        fixtures = [[NATIVE], [dict(RUN, status="in_progress", conclusion=None)], [RUN], JOBS]
        with patch.dict(os.environ, CONTEXT, clear=True), \
                patch.object(POLICY, "records", side_effect=fixtures), \
                patch.object(POLICY.time, "monotonic", side_effect=[0, 1]), \
                patch.object(POLICY.time, "sleep") as sleep:
            self.assertIn(SHA, POLICY.verify_default(["rust", "actions"]))
            sleep.assert_called_once_with(15)

    def test_api_errors_never_turn_into_unavailability_or_success(self):
        context = {"GITHUB_API_URL": "https://api.github.com", "GH_TOKEN": "fixture"}
        errors = [HTTPError("https://api.github.com", 403, "Forbidden", {}, None),
                  HTTPError("https://api.github.com", 404, "Not found", {}, None),
                  HTTPError("https://api.github.com", 503, "Unavailable", {}, None),
                  URLError("connection unavailable")]
        for error in errors:
            with self.subTest(error=type(error).__name__), patch.dict(os.environ, context, clear=True), \
                    patch.object(POLICY, "build_opener") as opener, self.assertRaises(RuntimeError):
                opener.return_value.open.side_effect = error
                POLICY.get_json("/repos/example/project/actions/workflows")
        with patch.dict(os.environ, context, clear=True), patch.object(POLICY, "build_opener") as opener, \
                self.assertRaises(json.JSONDecodeError):
            opener.return_value.open.return_value = io.BytesIO(b"invalid JSON")
            POLICY.get_json("/repos/example/project/actions/workflows")

    def test_api_pagination_and_schema_are_checked(self):
        with patch.object(POLICY, "get_json", side_effect=[{"workflows": [{}] * 100}, {"workflows": [NATIVE]}]):
            self.assertEqual(POLICY.records("/actions/workflows", "workflows")[-1], NATIVE)
        for response in ({}, {"workflows": None}, {"workflows": "not a list"}):
            with patch.object(POLICY, "get_json", return_value=response), self.assertRaises(RuntimeError):
                POLICY.records("/actions/workflows", "workflows")

    def test_unavailable_is_visible_and_advanced_remains_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            summary = Path(temporary) / "summary"
            output = Path(temporary) / "output"
            context = {"CODEQL_MODE": "unavailable", "CODEQL_LANGUAGES": "rust", "REPOSITORY_PRIVATE": "true",
                       "GITHUB_STEP_SUMMARY": str(summary), "GITHUB_OUTPUT": str(output)}
            with patch.dict(os.environ, context, clear=True), patch.object(POLICY, "get_json") as api:
                POLICY.main()
                api.assert_not_called()
            self.assertEqual(output.read_text(), "run-advanced=false\n")
            self.assertIn("CodeQL was NOT run", summary.read_text())
            self.assertIn("coverage limitation", summary.read_text())
            output.unlink()
            with patch.dict(os.environ, context | {"CODEQL_MODE": "advanced", "REPOSITORY_PRIVATE": "false"}, clear=True):
                POLICY.main()
            self.assertEqual(output.read_text(), "run-advanced=true\n")
            output.unlink()
            with patch.dict(os.environ, context | {"REPOSITORY_PRIVATE": "false"}, clear=True), \
                    self.assertRaises(RuntimeError):
                POLICY.main()
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
