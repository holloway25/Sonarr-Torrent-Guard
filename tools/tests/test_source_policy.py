"""Source-policy changes use mocked APIs only; no real torrent actions."""

import copy
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from authorization import RoutineAuthorization, RULE, code_digest, scope_digest
from guard import GuardError, classify_source, load_config, recheck_candidate, run, source_policy_key
from safety import SafetyError
import production
from tools.tests import test_guard as guard_fixtures
from tools.tests import test_production as production_fixtures


class SourcePolicyTests(unittest.TestCase):
    def setUp(self):
        self.f = guard_fixtures.WorkflowTests()
        self.f.setUp()
        self.f.config["sonarr"]["HD"]["indexers"] = {
            "mode": "private_exclusions", "private": ["Private Source", "Private Source - Freeleech"]}

    def source(self, name):
        self.f.grab["data"] = {"indexer": name}

    def test_unlisted_identified_source_is_assessed_without_public_list(self):
        self.source("New Public Source")
        report = self.f.check()
        self.assertEqual(report["decision"], "would_fail")
        self.assertTrue(report["public_source_confirmed"])
        self.assertEqual(report["indexer"], "New Public Source")

    def test_private_exceptions_protect_case_whitespace_and_freeleech_aliases(self):
        for name in ("Private Source", "private source", " PRIVATE SOURCE ", "Private Source - Freeleech"):
            with self.subTest(name=name):
                self.f.qb.calls.clear()
                self.source(name)
                report = self.f.check()
                self.assertEqual(report["decision"], "skip")
                self.assertEqual(report.get("reason"), "private_source_protected")
                self.assertFalse(any(route.endswith("/files") for route, _ in self.f.qb.calls))

    def test_private_exception_wins_over_obsolete_public_list(self):
        policy = self.f.config["sonarr"]["HD"]["indexers"]
        policy["public"] = ["Private Source"]
        self.source("Private Source")
        self.assertEqual(self.f.check()["reason"], "private_source_protected")

    def test_missing_malformed_or_blank_source_is_not_assumed_public(self):
        for name in (None, "", " \t ", 7, {}, []):
            with self.subTest(kind=type(name).__name__):
                self.f.qb.calls.clear()
                self.source(name)
                self.assertEqual(self.f.check()["reason"], "missing_indexer_identity")
                self.assertFalse(any(route.endswith("/files") for route, _ in self.f.qb.calls))
        self.f.grab["data"] = {}
        self.assertEqual(self.f.check()["reason"], "missing_indexer_identity")

    def test_ambiguous_sources_still_block_even_if_both_are_unlisted(self):
        self.source("New Public Source")
        row = dict(self.f.row, id=2, episodeId=5)
        grab = dict(self.f.grab, id=5, episodeId=5, data={"indexer": "Another Public Source"})
        self.f.s.routes["/api/v3/queue"] = {"totalRecords": 2, "records": [self.f.row, row]}
        self.f.s.routes["/api/v3/history"] = {"totalRecords": 2, "records": [self.f.grab, grab]}
        self.assertEqual(self.f.check()["reason"], "ambiguous_indexer_identity")

    def test_bad_file_rules_still_apply_and_good_media_is_kept(self):
        self.source("New Public Source")
        self.assertIn("contains_exe", self.f.check()["reasons"])
        self.f.qb.routes["/api/v2/torrents/files"] = guard_fixtures.manifest(("episode.mkv", 1))
        self.assertEqual(self.f.check()["decision"], "keep")

    def test_manual_torrent_without_grab_history_stays_protected(self):
        self.f.s.routes["/api/v3/history"] = {"totalRecords": 0, "records": []}
        self.assertEqual(self.f.check()["reason"], "no_sonarr_grab_history")

    def test_legacy_policy_does_not_silently_become_default_public(self):
        self.f.config["sonarr"]["HD"]["indexers"] = {"public": ["Public Source"], "private": ["Private Source"]}
        self.source("New Public Source")
        self.assertEqual(self.f.check().get("reason"), "unclassified_source_protected")

    def test_policy_mode_and_exceptions_are_bound_to_approval_identity(self):
        policy = self.f.config["sonarr"]["HD"]["indexers"]
        first = self.f.check()["ownership_fingerprint"]
        policy["private"].append("Another Private Source")
        second = self.f.check()["ownership_fingerprint"]
        self.assertNotEqual(first, second)
        policy.update(mode="public_allowlist", public=["Public Source"])
        self.assertNotEqual(second, self.f.check()["ownership_fingerprint"])

    def test_fresh_recheck_blocks_source_added_to_private_exceptions(self):
        self.source("New Public Source")
        report = self.f.check()
        self.f.config["sonarr"]["HD"]["indexers"]["private"].append("New Public Source")
        with self.assertRaises(SafetyError):
            recheck_candidate(report, self.f.config, self.f.qb, {"HD": self.f.s})

    def test_invalid_policy_and_lists_are_rejected(self):
        for policy in (None, {}, {"mode": "typo", "private": []},
                       {"mode": "private_exclusions"}, {"mode": "private_exclusions", "private": "source"},
                       {"mode": "private_exclusions", "private": [None]},
                       {"mode": "private_exclusions", "private": [" "]}):
            with self.subTest(policy=policy), self.assertRaises(GuardError):
                source_policy_key(policy)
        self.assertEqual(classify_source({"mode": "private_exclusions", "private": []}, "Named Source"), "public")
        self.assertEqual(classify_source({"mode": "private_exclusions", "private": []}, None), "unknown")

    def test_config_loader_accepts_private_only_and_legacy_formats(self):
        sample = json.loads((Path(__file__).resolve().parents[2] / "config.example.json").read_text())
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "settings.json"
            for legacy in (False, True):
                value = copy.deepcopy(sample)
                if legacy:
                    for instance in value["sonarr"].values():
                        instance["indexers"].pop("mode")
                        instance["indexers"]["public"] = ["Public Source"]
                path.write_text(json.dumps(value)); path.chmod(0o600)
                self.assertEqual(load_config(path), value)

    def production_fixture(self):
        f = production_fixtures.ProductionTests()
        f.setUp()
        self.addCleanup(f.doCleanups)
        self.addCleanup(f.tearDown)
        f.config["sonarr"]["HD"]["indexers"] = {"mode": "private_exclusions", "private": ["Private Source"]}
        f.grab["data"]["indexer"] = "New Public Source"
        f.report = run(f.config, f.qb, f.apis)[0]
        f.journal.allow_public_attempt = True
        now = time.time()
        grant = {"enabled": True, "rule": RULE, "grant_id": "c" * 64, "issued_at": now - 1,
                 "expires_at": now + 3600, "scope_digest": scope_digest(f.config), "code_digest": code_digest()}
        return f, grant, RoutineAuthorization(grant, f.config)

    def test_routine_sender_accepts_unlisted_source_only_under_explicit_grant(self):
        f, _, authority = self.production_fixture()
        def results(*args):
            f.results()
            for row in f.s.routes["/api/v3/blocklist"]["records"]:
                row["indexer"] = "New Public Source"
        with patch("production.ROUTINE_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=results) as send:
            row = production.execute_routine_attempt(f.config, f.qb, f.apis, f.journal, f.report, authority)
        self.assertEqual(row["stage"], "cleanup_resolved")
        send.assert_called_once()

    def test_routine_rejects_private_missing_and_malformed_sources(self):
        f, _, authority = self.production_fixture()
        for name in ("Private Source", " private SOURCE ", None, "", 7):
            with self.subTest(kind=type(name).__name__), self.assertRaises(SafetyError):
                authority.validate(f.config, dict(f.report, indexer=name))

    def test_source_policy_change_invalidates_previous_grant(self):
        f, _, authority = self.production_fixture()
        before = scope_digest(f.config)
        f.config["sonarr"]["HD"]["indexers"].update(mode="public_allowlist", public=["New Public Source"])
        self.assertNotEqual(before, scope_digest(f.config))
        with self.assertRaisesRegex(SafetyError, "routine_authorization_expired_or_scope_changed"):
            authority.validate(f.config, f.report)

    def test_mode_alone_changes_grant_scope_even_with_identical_lists(self):
        f, grant, _ = self.production_fixture()
        policy = f.config["sonarr"]["HD"]["indexers"]
        policy["public"] = ["New Public Source"]
        grant["scope_digest"] = scope_digest(f.config)
        authority = RoutineAuthorization(grant, f.config)
        before = scope_digest(f.config)
        policy["mode"] = "public_allowlist"
        self.assertNotEqual(before, scope_digest(f.config))
        with self.assertRaises(SafetyError):
            authority.validate(f.config, f.report)

    def test_source_becoming_private_during_final_dispatch_blocks_send(self):
        f, _, authority = self.production_fixture()
        calls = []
        def connection(*args):
            calls.append(1)
            if len(calls) == 3:
                f.config["sonarr"]["HD"]["indexers"]["private"].append("New Public Source")
        with patch("production.ROUTINE_RELEASE_ENABLED", True), patch(
                "production.require_connectivity", side_effect=connection), patch("production._send_queue_delete") as send:
            row = production.execute_routine_attempt(f.config, f.qb, f.apis, f.journal, f.report, authority)
        self.assertIn(row["stage"], ("cancelled", "dispatch_blocked"))
        send.assert_not_called()


if __name__ == "__main__":
    unittest.main()
