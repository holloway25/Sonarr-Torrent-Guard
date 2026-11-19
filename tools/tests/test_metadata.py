import datetime
import json
import time
import unittest
from unittest.mock import Mock, patch

from guard import run, recheck_candidate
import production
from safety import SafetyError, check_fresh
from workflow import preview_failure
from reports import human_report, json_events
from tools.tests import test_guard as guard_fixtures
from tools.tests import test_production as production_fixtures


class MetadataTests(unittest.TestCase):
    def setUp(self):
        self.f = guard_fixtures.WorkflowTests()
        self.f.setUp()
        self.t = self.f.qb.routes["/api/v2/torrents/info"][0]
        self.t.update(state="metaDL", total_size=-1, progress=0, time_active=1800)
        self.f.qb.routes["/api/v2/torrents/files"] = []

    def assess(self, now=1900):
        return run(self.f.config, self.f.qb, {"HD": self.f.s}, now=now)[0]

    def test_public_metadata_timeout_is_separate_from_empty_or_unselected_files(self):
        report = self.assess()
        self.assertEqual(report["decision"], "would_fail")
        self.assertEqual(report["reasons"], ["metadata_timeout"])
        self.assertEqual(report["file_count"], 0)
        self.assertNotIn("contains_exe", report["reasons"])
        self.t["state"] = "forcedMetaDL"
        self.assertEqual(self.assess()["decision"], "would_fail")

    def test_requires_elapsed_age_but_does_not_depend_on_stalled_active_counter(self):
        self.assertEqual(self.assess(1899)["reason"], "metadata_timeout_not_reached")
        for active in (None, True, -1, 1799, 1800.0):
            self.t["time_active"] = active
            self.assertEqual(self.assess()["decision"], "would_fail")

    def test_private_unknown_manual_and_wrong_client_are_still_protected(self):
        for source in ("Private Source", "Unknown Source"):
            self.f.s.routes["/api/v3/history"]["records"][0]["data"]["indexer"] = source
            self.assertEqual(self.assess()["decision"], "skip")
        self.f.s.routes["/api/v3/history"]["records"][0]["data"]["indexer"] = "Public Source"
        self.f.s.routes["/api/v3/queue"]["records"][0]["downloadClient"] = "Other"
        self.assertEqual(self.assess()["decision"], "skip")
        self.f.s.routes["/api/v3/queue"]["records"][0]["downloadClient"] = "Downloader"
        self.f.s.routes["/api/v3/history"] = {"totalRecords": 0, "records": []}
        self.assertEqual(self.assess()["reason"], "no_sonarr_grab_history")

    def test_inconsistent_state_or_file_response_does_not_prove_metadata_timeout(self):
        for files in (None, {}, [{"name": "payload.exe"}], guard_fixtures.manifest(("video.mkv", 1))):
            self.f.qb.routes["/api/v2/torrents/files"] = files
            self.assertEqual(self.assess()["reason"], "metadata_state_inconsistent")
        self.f.qb.routes["/api/v2/torrents/files"] = []
        for changes in ({"progress": True}, {"progress": .1}, {"total_size": 123}, {"total_size": None}):
            original = dict(self.t)
            self.t.update(changes)
            self.assertEqual(self.assess()["reason"], "metadata_state_inconsistent")
            self.t.update(original)

    def test_paused_stopped_or_empty_known_download_is_not_failed_by_timeout(self):
        for state in ("pausedDL", "stoppedDL", "checkingDL", "error"):
            self.t["state"] = state
            self.assertEqual(self.assess()["decision"], "skip")

    def test_metadata_human_and_json_proposals_do_not_promise_blocklisting(self):
        report = self.assess()
        self.assertNotIn("blocklist_release_in_owning_sonarr", report["proposed_actions"])
        self.assertIn("remove_torrent_and_data_through_sonarr_without_blocklisting", report["proposed_actions"])
        self.assertIn("request_owning_sonarr_episode_search_after_confirmed_removal_and_final_checks", report["proposed_actions"])
        output = human_report([report], {}, "test time")
        self.assertIn("WITHOUT blocklisting", output)
        self.assertIn("affected-episode search", output)
        self.assertNotIn("blocklists and handles retry", output)
        event = list(json_events([report], {}, "test time"))[0]
        self.assertEqual(event["proposed_actions"], report["proposed_actions"])

    def test_file_failure_human_and_json_proposals_show_native_sonarr_cleanup(self):
        self.t["state"] = "stalledUP"
        self.f.qb.routes["/api/v2/torrents/files"] = guard_fixtures.manifest(("payload.exe", 0))
        report = self.assess()
        self.assertIn("blocklist_release_in_owning_sonarr", report["proposed_actions"])
        output = human_report([report], {}, "test time")
        self.assertIn("blocklists and handles retry", output)
        event = list(json_events([report], {}, "test time"))[0]
        self.assertEqual(event["proposed_actions"], report["proposed_actions"])


class MetadataSenderTests(unittest.TestCase):
    def setUp(self):
        self.f = production_fixtures.ProductionTests()
        self.f.setUp()
        self.t = self.f.qb.routes["/api/v2/torrents/info"][0]
        # Fixture's torrent is ten minutes old; use a matching older grab.
        self.t["added_on"] -= 1800
        from datetime import datetime, timezone
        self.f.grab["date"] = datetime.fromtimestamp(self.t["added_on"], timezone.utc).isoformat()
        self.t.update(state="metaDL", progress=0, total_size=-1, time_active=1800)
        self.f.qb.routes["/api/v2/torrents/files"] = []
        self.f.report = run(self.f.config, self.f.qb, self.f.apis)[0]
        gate = patch("production.METADATA_RETRY_RELEASE_ENABLED", True)
        gate.start()
        self.addCleanup(gate.stop)

    def tearDown(self):
        self.f.tearDown()
        self.f.doCleanups()

    def routine_authority(self):
        from authorization import RULE, RoutineAuthorization, code_digest, scope_digest

        config = self.f.config
        now = time.time()
        return RoutineAuthorization({"enabled": True, "rule": RULE, "grant_id": "e" * 64,
                                     "issued_at": now - 1, "expires_at": now + 900,
                                     "scope_digest": scope_digest(config), "code_digest": code_digest()}, config)

    def test_conflicting_tied_grabs_hold_routine_but_distinguishably_later_public_grab_passes(self):
        f = self.f
        authority = self.routine_authority()
        history = "/api/v3/history"
        tied = [dict(f.grab, id=4, data={**f.grab["data"], field: value})
                for field, value in (("indexer", "Private Source"), ("downloadClientName", "Other Downloader"))]
        with patch("production.ROUTINE_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=self.removed) as remove, patch(
                "production._send_episode_search", return_value=41) as search:
            for conflict in tied:
                with self.subTest(data=conflict["data"]):
                    f.s.routes[history] = {"totalRecords": 2, "records": [conflict, f.grab]}
                    assessed, = run(f.config, f.qb, f.apis)
                    self.assertEqual((assessed["decision"], assessed["reason"]),
                                     ("skip", "conflicting_grab_source_order"))
                    with self.assertRaisesRegex(SafetyError, "^candidate_no_longer_eligible$"):
                        production.execute_live_metadata_retry(f.config, f.qb, f.apis, f.report, authority, f.lock_path)
            remove.assert_not_called()
            search.assert_not_called()

            older = datetime.datetime.fromisoformat(f.grab["date"]) - datetime.timedelta(seconds=1)
            f.s.routes[history] = {"totalRecords": 2, "records": [dict(tied[0], date=older.isoformat()), f.grab]}
            row = production.execute_live_metadata_retry(f.config, f.qb, f.apis, f.report, authority, f.lock_path)
        self.assertEqual(row["stage"], "retry_requested")
        remove.assert_called_once_with(f.s, 7, blocklist=False)
        search.assert_called_once()

    def test_targeted_qbittorrent_checks_are_the_last_remote_reads_before_removal(self):
        f = self.f
        authority = self.routine_authority()
        calls = []

        qb_call, sonarr_call = f.qb.call, f.s.call

        def qb(route, params=None):
            calls.append(("qb", route, params))
            return qb_call(route, params)

        def sonarr(route, params=None):
            calls.append(("sonarr", route, params))
            return sonarr_call(route, params)

        def remove(*args, **kwargs):
            self.assertEqual(calls[-2:], [
                ("qb", "/api/v2/torrents/info", {"hashes": f.hash}),
                ("qb", "/api/v2/torrents/files", {"hash": f.hash}),
            ])
            self.removed()

        with patch("production.ROUTINE_RELEASE_ENABLED", True), patch.object(
                f.qb, "call", side_effect=qb), patch.object(f.s, "call", side_effect=sonarr), patch(
                "production._send_queue_delete", side_effect=remove) as send, patch(
                "production._send_episode_search", return_value=41):
            row = production.execute_live_metadata_retry(f.config, f.qb, f.apis, f.report, authority, f.lock_path)
        self.assertEqual(row["stage"], "retry_requested")
        send.assert_called_once_with(f.s, 7, blocklist=False)

    def test_final_metadata_check_holds_a_download_that_started(self):
        f = self.f
        capture = production.capture_context

        def capture_then_start(*args):
            context = capture(*args)
            self.t.update(state="downloading", progress=0.15, total_size=100)
            f.qb.routes["/api/v2/torrents/files"] = guard_fixtures.manifest(("episode.mkv", 1))
            return context

        with patch("production.ROUTINE_RELEASE_ENABLED", True), patch(
                "production.capture_context", side_effect=capture_then_start), patch(
                "production._send_queue_delete") as remove, patch("production._send_episode_search") as search:
            with self.assertRaisesRegex(SafetyError, "^metadata_timeout_no_longer_confirmed$"):
                self.execute()
        remove.assert_not_called()
        search.assert_not_called()

    def test_final_history_rejects_malformed_potential_replacements(self):
        import copy

        f = self.f
        sonarr, downloader = copy.deepcopy(f.s.routes), copy.deepcopy(f.qb.routes)
        observe = production.OutcomeVerifier.observe
        for change, reason in (
                ({"seriesId": None}, "replacement_history_identity_invalid"),
                ({"episodeId": "3"}, "replacement_history_identity_invalid"),
                ({"eventType": None}, "replacement_history_event_invalid"),
                ({"data": {}}, "replacement_client_unknown"),
                ({}, "replacement_already_grabbed")):
            with self.subTest(change=change):
                f.s.routes, f.qb.routes = copy.deepcopy(sonarr), copy.deepcopy(downloader)

                def observe_then_add_grab(verifier):
                    result = observe(verifier)
                    stamp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=1)
                    grab = dict(f.grab, id=20, downloadId="b" * 40, date=stamp.isoformat())
                    grab.update(change)
                    f.s.routes["/api/v3/history/since"] = [f.grab, grab]
                    return result

                with patch("production.ROUTINE_RELEASE_ENABLED", True), patch.object(
                        production.OutcomeVerifier, "observe", observe_then_add_grab), patch(
                        "production._send_queue_delete", side_effect=self.removed), patch(
                        "production._send_episode_search") as search:
                    result = self.execute()
                self.assertEqual((result["stage"], result["stop_reason"]), ("retry_search_blocked", reason))
                search.assert_not_called()

    def test_standalone_scope_change_after_removal_blocks_search(self):
        import copy
        from pathlib import Path

        f = self.f
        authority = self.routine_authority()
        folder = Path(f.folder.name)
        config_path = folder / "connections.json"
        grant_path = folder / "routine-authorization.json"
        config = copy.deepcopy(f.config)
        config["dry_run"] = True
        config["qbittorrent"].update(username="REPLACE_ME", password="REPLACE_ME")
        config_path.write_text(json.dumps(config))
        grant_path.write_text(json.dumps(authority.value))
        grant_path.chmod(0o600)
        loaded = type(authority).load(grant_path, f.config, config_path=config_path)

        def remove_then_protect(*args, **kwargs):
            self.removed()
            policy = config["sonarr"]["HD"]["indexers"]
            policy.update(public=[], private=["Public Source", "Private Source"])
            config_path.write_text(json.dumps(config))

        with patch("production.ROUTINE_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=remove_then_protect), patch(
                "production._send_episode_search") as search:
            result = production.execute_live_metadata_retry(f.config, f.qb, f.apis, f.report, loaded, f.lock_path)
        self.assertEqual(result["stop_reason"], "routine_authorization_expired_or_scope_changed")
        search.assert_not_called()

    def removed(self, *args, **kwargs):
        self.f.qb.routes["/api/v2/torrents/info"] = []
        self.f.s.routes["/api/v3/queue"] = {"totalRecords": 0, "records": []}

    def execute(self):
        f = self.f
        return production.execute_live_metadata_retry(f.config, f.qb, f.apis, f.report, self.routine_authority(), f.lock_path)

    def test_metadata_retry_requires_separate_release_gate(self):
        with patch("production.METADATA_RETRY_RELEASE_ENABLED", False), patch(
                "production.ROUTINE_RELEASE_ENABLED", True), patch("production._send_queue_delete") as send:
            with self.assertRaisesRegex(SafetyError, "metadata_retry_not_released"):
                self.execute()
        send.assert_not_called()

    def test_original_present_under_an_alternate_hash_stops_retry(self):
        f = self.f
        hybrid = dict(self.t, hash="b" * 40, infohash_v1=f.hash, infohash_v2="b" * 64)

        def remove_from_queue_only(*args, **kwargs):
            self.removed()
            f.qb.routes["/api/v2/torrents/info"] = [hybrid]

        with patch("production.ROUTINE_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=remove_from_queue_only) as remove, patch(
                "production._send_episode_search") as search:
            row = self.execute()
        self.assertNotIn("hash_aliases", f.report)
        self.assertEqual(row["stage"], "retry_removal_unverified")
        remove.assert_called_once()
        search.assert_not_called()

    def test_new_queued_replacement_blocks_extra_search(self):
        def removed(*args, **kwargs):
            self.removed()
            self.f.s.routes["/api/v3/queue"] = {"totalRecords": 1,
                "records": [{"id": 19, "seriesId": 2, "episodeId": 3}]}
        with patch("production.ROUTINE_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=removed), patch("production._send_episode_search") as search:
            row = self.execute()
        self.assertEqual(row["stage"], "retry_search_blocked")
        self.assertEqual(row["stop_reason"], "replacement_already_queued")
        search.assert_not_called()

    def test_preview_describes_remove_then_search_not_failure_and_blocklist(self):
        plan = preview_failure(self.f.report, {"status": "verified", "automatic_retry": True, "interactive_retry": True})
        self.assertIs(plan["request_preview"]["params"]["blocklist"], False)
        self.assertIs(plan["request_preview"]["params"]["skipRedownload"], True)
        self.assertEqual(plan["search_preview"]["body"], {"name": "EpisodeSearch", "episodeIds": [3]})
        self.assertIn("explicit_metadata_retry_authorization_required", plan["blockers"])

    def test_preexisting_new_grab_suppresses_redundant_search(self):
        def removed(*args, **kwargs):
            self.removed()
            replacement = dict(self.f.grab, id=8, downloadId="b" * 40,
                date=datetime.datetime.now(datetime.timezone.utc).isoformat())
            self.f.s.routes["/api/v3/history/since"] = [self.f.grab, replacement]
        with patch("production.ROUTINE_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=removed), patch("production._send_episode_search") as search:
            row = self.execute()
        self.assertEqual(row["stage"], "retry_superseded")
        search.assert_not_called()

    def test_later_episode_history_failure_preserves_an_already_confirmed_grab(self):
        f = self.f
        self.assess_season_pack()
        baseline = f.s.routes["/api/v3/history/since"][:]
        original = f.s.call
        removed = False
        failed_at = []

        def remove(*args, **kwargs):
            nonlocal removed
            self.removed()
            removed = True
            stamp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=1)
            replacement = dict(f.grab, id=9, episodeId=3, downloadId="b" * 40, date=stamp.isoformat())
            f.s.routes["/api/v3/history/since"] = [*baseline, replacement]

        def episode_history(route, params=None):
            if (removed and route == "/api/v3/history" and params.get("episodeId") == 4
                    and "eventType" not in params):
                failed_at.append(4)
                f.s.routes["/api/v3/history/since"] = baseline
                raise TimeoutError()
            return original(route, params)

        with patch("production.ROUTINE_RELEASE_ENABLED", True), patch.object(
                f.s, "call", side_effect=episode_history), patch(
                "production._send_queue_delete", side_effect=remove), patch(
                "production._send_episode_search") as search:
            row = self.execute()
        self.assertEqual(failed_at, [4])
        self.assertEqual(row["stage"], "retry_superseded")
        search.assert_not_called()

    def test_metadata_preflight_reports_replacement_grab_observations(self):
        from contextlib import redirect_stdout
        from io import StringIO

        f = self.f
        stamp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=1)
        replacement = dict(f.grab, id=20, downloadId="b" * 40, date=stamp.isoformat())
        original = f.s.call
        f.qb.login = Mock()

        def call(route, params=None):
            if route == "/api/v3/history" and "eventType" not in params:
                return {"totalRecords": 1, "records": [replacement]}
            return original(route, params)

        args = ["production.py", "--config", "connections.json", "--preflight", "HD", f.hash]
        with patch("sys.argv", args), patch("production.load_config", return_value=f.config), patch(
                "production.Api", side_effect=[f.qb, f.s]), patch.object(f.s, "call", side_effect=call), redirect_stdout(StringIO()) as output:
            self.assertEqual(production.main(), 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result["preflight"], "verified")
        self.assertIs(result["live_sender_enabled"], False)
        observation = result["observation"]
        self.assertIs(observation.get("replacement_grab_observed"), True)
        self.assertIs(observation.get("any_replacement_observed"), True)
        self.assertIs(observation.get("replacement_grab_ambiguous"), False)

    def test_later_page_timeout_preserves_the_grab_seen_on_the_first_page(self):
        f = self.f
        original = f.s.call
        after_remove = False
        seen_pages = []

        def remove(*args, **kwargs):
            nonlocal after_remove
            self.removed()
            after_remove = True

        def paginated(route, params=None):
            if not after_remove or route != "/api/v3/history" or "eventType" in params:
                return original(route, params)
            seen_pages.append(params["page"])
            if params["page"] == 2:
                raise TimeoutError()
            stamp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=1)
            replacement = dict(f.grab, id=20, downloadId="b" * 40, date=stamp.isoformat())
            rows = [replacement, *(dict(replacement, id=n, eventType="downloadFailed") for n in range(21, 120))]
            return {"records": rows, "totalRecords": 101}

        with patch("production.ROUTINE_RELEASE_ENABLED", True), patch.object(
                f.s, "call", side_effect=paginated), patch(
                "production._send_queue_delete", side_effect=remove), patch(
                "production._send_episode_search") as search:
            row = self.execute()
        self.assertEqual(seen_pages, [1, 2])
        self.assertEqual(row["stage"], "retry_superseded")
        search.assert_not_called()

    def test_final_queue_requests_unknown_series_and_blocks_search(self):
        f = self.f
        call = f.s.call

        def remove_with_unmapped_item(*args, **kwargs):
            self.removed()
            f.s.routes["/api/v3/queue"] = {"totalRecords": 1, "records": [
                {"id": 18, "seriesId": None, "episodeId": None}]}

        def sonarr_queue(route, params=None):
            result = call(route, params)
            if route == "/api/v3/queue" and params.get("includeUnknownSeriesItems") != "true":
                result["records"] = [r for r in result["records"] if r["seriesId"] is not None]
                result["totalRecords"] = len(result["records"])
            return result

        with patch("production.ROUTINE_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=remove_with_unmapped_item) as send, patch.object(
                f.s, "call", side_effect=sonarr_queue), patch("production._send_episode_search") as search:
            row = self.execute()
        self.assertEqual(row["stage"], "retry_search_blocked")
        self.assertEqual(row["stop_reason"], "replacement_queue_identity_invalid")
        send.assert_called_once()
        search.assert_not_called()

    def assess_season_pack(self):
        f = self.f
        first = f.s.routes["/api/v3/queue"]["records"][0]
        second = dict(first, id=8, episodeId=4)
        f.s.routes["/api/v3/queue"] = {"totalRecords": 2, "records": [first, second]}
        grabs = [f.grab, dict(f.grab, id=6, episodeId=4)]
        f.s.routes["/api/v3/history"] = {"totalRecords": 2, "records": grabs}
        f.s.routes["/api/v3/history/since"] = grabs
        f.report = run(f.config, f.qb, f.apis)[0]
        return second

    def test_final_queue_ignores_both_stale_original_season_pack_rows(self):
        f = self.f
        self.assess_season_pack()

        def remove_from_downloader_only(*args, **kwargs):
            f.qb.routes["/api/v2/torrents/info"] = []

        with patch("production.ROUTINE_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=remove_from_downloader_only) as send, patch(
                "production._send_episode_search", return_value=41) as search:
            row = self.execute()
        self.assertEqual(row["stage"], "retry_requested")
        send.assert_called_once_with(f.s, 7, blocklist=False)
        search.assert_called_once_with(f.s, [3, 4])

    def blocklist_one_episode(self):
        f = self.f
        stamp = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=1)).isoformat()
        f.s.routes["/api/v3/blocklist"] = {"totalRecords": 1, "records": [
            {"id": 33, "seriesId": 2, "episodeIds": [4], "indexer": "Public Source", "protocol": "torrent",
             "sourceTitle": f.grab["sourceTitle"], "date": stamp}]}

    def test_pre_removal_grab_stays_a_search_veto_after_baseline_refresh(self):
        f = self.f
        stamp = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=1)).isoformat()
        grabbed = dict(f.grab, id=33, downloadId="b" * 40, date=stamp)

        def record_grab(*args):
            f.s.routes["/api/v3/history/since"].append(grabbed)

        def remove(*args, **kwargs):
            self.removed()
            f.s.routes["/api/v3/history/since"].remove(grabbed)

        with patch("production.ROUTINE_RELEASE_ENABLED", True), patch(
                "production.wait_for_event_boundary", side_effect=record_grab), patch(
                "production._send_queue_delete", side_effect=remove) as delete, patch(
                "production._send_episode_search") as search:
            row = self.execute()
        self.assertEqual(row["stage"], "retry_search_blocked")
        self.assertEqual(row["stop_reason"], "replacement_already_grabbed")
        delete.assert_called_once()
        search.assert_not_called()

    def test_missing_blocklist_identity_holds_final_search(self):
        import copy

        f = self.f
        sonarr, downloader = copy.deepcopy(f.s.routes), copy.deepcopy(f.qb.routes)
        for field, mismatch_field in (("indexer", "sourceTitle"), ("sourceTitle", "indexer")):
            for mismatch in (False, True):
                with self.subTest(field=field, mismatch=mismatch):
                    f.s.routes, f.qb.routes = copy.deepcopy(sonarr), copy.deepcopy(downloader)
                    self.assert_incomplete_blocklist_result(field, mismatch_field if mismatch else None)

    def assert_incomplete_blocklist_result(self, field, mismatch_field):
        f = self.f
        self.assess_season_pack()
        observe = production.OutcomeVerifier.observe

        def inject_after_observation(verifier):
            result = observe(verifier)
            self.blocklist_one_episode()
            record = f.s.routes["/api/v3/blocklist"]["records"][0]
            del record[field]
            if mismatch_field:
                record[mismatch_field] = "Known different"
            return result

        with patch("production.ROUTINE_RELEASE_ENABLED", True), patch.object(
                production.OutcomeVerifier, "observe", inject_after_observation), patch(
                "production._send_queue_delete", side_effect=self.removed), patch(
                "production._send_episode_search", return_value=41) as search:
            result = self.execute()
        if mismatch_field:
            self.assertEqual(result["stage"], "retry_requested")
            search.assert_called_once()
        else:
            self.assertEqual(result["stage"], "retry_search_blocked")
            self.assertEqual(result["stop_reason"], "replacement_blocklist_uncertain")
            search.assert_not_called()

    def test_missing_episode_evidence_holds_but_unrelated_and_usenet_rows_do_not(self):
        import copy

        f = self.f
        self.assess_season_pack()
        sonarr, downloader = copy.deepcopy(f.s.routes), copy.deepcopy(f.qb.routes)
        for ids, protocol, held in (([], "torrent", True), ([99], "torrent", False), ([4], "usenet", False)):
            with self.subTest(ids=ids, protocol=protocol):
                f.s.routes, f.qb.routes = copy.deepcopy(sonarr), copy.deepcopy(downloader)

                def remove(*args, **kwargs):
                    self.removed()
                    self.blocklist_one_episode()
                    f.s.routes["/api/v3/blocklist"]["records"][0].update(episodeIds=ids, protocol=protocol)

                with patch("production.ROUTINE_RELEASE_ENABLED", True), patch(
                        "production._send_queue_delete", side_effect=remove), patch(
                        "production._send_episode_search", return_value=41) as search:
                    result = self.execute()
                if held:
                    self.assertEqual(result["stage"], "retry_search_blocked")
                    self.assertEqual(result["stop_reason"], "replacement_blocklist_uncertain")
                    search.assert_not_called()
                else:
                    self.assertEqual(result["stage"], "retry_requested")
                    search.assert_called_once_with(f.s, [3, 4])

    def test_metadata_partial_pack_blocklist_stops_retry(self):
        self.assess_season_pack()

        def remove(*args, **kwargs):
            self.removed()
            self.blocklist_one_episode()

        with patch("production.ROUTINE_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=remove), patch(
                "production._send_episode_search") as search:
            row = self.execute()
        self.assertEqual(row["stage"], "retry_search_blocked")
        search.assert_not_called()

    def test_metadata_recovers_with_same_properties_fallback_as_assessment(self):
        f = self.f
        unrelated = "d" * 40
        torrent = {"hash": unrelated, "category": "other"}
        f.qb.routes["/api/v2/torrents/info"].append(torrent)

        def remove_then_keep_unrelated(*args, **kwargs):
            self.removed()
            f.qb.routes["/api/v2/torrents/info"] = [torrent]
            f.qb.calls.clear()

        with patch("production.ROUTINE_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=remove_then_keep_unrelated), patch(
                "production._send_episode_search", return_value=41) as search:
            row = self.execute()
        self.assertEqual(row["stage"], "retry_requested")
        self.assertEqual([params["hash"] for route, params in f.qb.calls if route.endswith("/properties")],
                         [unrelated, unrelated])
        search.assert_called_once_with(f.s, [3])

    def test_final_queue_blocks_replacement_reusing_original_season_pack_row_id(self):
        f = self.f
        second = self.assess_season_pack()

        def remove_and_replace(*args, **kwargs):
            f.qb.routes["/api/v2/torrents/info"] = []
            second["downloadId"] = "b" * 40

        with patch("production.ROUTINE_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=remove_and_replace) as send, patch(
                "production._send_episode_search") as search:
            row = self.execute()
        self.assertEqual(row["stage"], "retry_search_blocked")
        self.assertEqual(row["stop_reason"], "replacement_already_queued")
        send.assert_called_once()
        search.assert_not_called()

    def test_unexpected_blocklisting_requires_review_not_another_search(self):
        with patch("production.ROUTINE_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=lambda *a, **kw: self.f.results()), patch(
                "production._send_episode_search") as search:
            row = self.execute()
        self.assertEqual(row["stage"], "retry_search_blocked")
        search.assert_not_called()

class MetadataTransportTests(unittest.TestCase):
    def setUp(self):
        self.api = Mock(config={"url": "https://sonarr.example.invalid", "api_key": "REPLACE_ME"}, deadline=None)
        self.response = Mock(status=201)
        self.response.__enter__ = Mock(return_value=self.response)
        self.response.__exit__ = Mock(return_value=False)
        self.response.read.return_value = b'{"id":41,"name":"EpisodeSearch","body":{"episodeIds":[3]}}'
        self.opener = Mock()
        self.opener.open.return_value = self.response

    def test_soft_removal_params_and_exact_episode_search_command(self):
        with patch("production.METADATA_RETRY_RELEASE_ENABLED", True), patch(
                "production.ROUTINE_RELEASE_ENABLED", True), patch(
                "urllib.request.build_opener", return_value=self.opener):
            production._send_queue_delete(self.api, 7, blocklist=False)
            request = self.opener.open.call_args.args[0]
            self.assertEqual(request.get_method(), "DELETE")
            for param in ("removeFromClient=true", "blocklist=false", "skipRedownload=true", "changeCategory=false"):
                self.assertIn(param, request.full_url)
            self.assertEqual(production._send_episode_search(self.api, [3]), 41)
        request = self.opener.open.call_args.args[0]
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.full_url, "https://sonarr.example.invalid/api/v3/command")
        self.assertEqual(json.loads(request.data), {"name": "EpisodeSearch", "episodeIds": [3]})

    def test_search_and_soft_removal_refuse_disabled_release_gate(self):
        with patch("production.METADATA_RETRY_RELEASE_ENABLED", False), patch(
                "production.ROUTINE_RELEASE_ENABLED", True), patch("urllib.request.build_opener") as opener:
            with self.assertRaises(SafetyError):
                production._send_episode_search(self.api, [3])
            with self.assertRaises(SafetyError):
                production._send_queue_delete(self.api, 7, blocklist=False)
        opener.assert_not_called()

    def test_malformed_or_lost_search_receipt_is_uncertain_not_retried_or_disclosed(self):
        for payload in (b'{"id":true,"name":"EpisodeSearch"}', b'{"id":0,"name":"EpisodeSearch"}',
                        b'{"id":41,"name":"SeriesSearch"}', b'{"id":41,"name":"EpisodeSearch"}',
                        b'{"id":41,"name":"EpisodeSearch","body":{"episodeIds":[4]}}',
                        b'{"id":41,"id":42,"name":"EpisodeSearch","body":{"episodeIds":[3]}}',
                        b'private-response', b'x' * 65537):
            self.response.read.return_value = payload
            self.opener.reset_mock()
            with self.subTest(payload_size=len(payload)), patch("production.METADATA_RETRY_RELEASE_ENABLED", True), patch(
                    "production.ROUTINE_RELEASE_ENABLED", True), patch(
                    "urllib.request.build_opener", return_value=self.opener):
                with self.assertRaisesRegex(SafetyError, "^episode_search_outcome_uncertain$"):
                    production._send_episode_search(self.api, [3])
            self.opener.open.assert_called_once()

    def test_episode_search_rejects_invalid_targets_before_transport(self):
        with patch("production.METADATA_RETRY_RELEASE_ENABLED", True), patch(
                "production.ROUTINE_RELEASE_ENABLED", True), patch("urllib.request.build_opener") as opener:
            for ids in ([], [True], [-1], [3, 3], None):
                with self.subTest(ids=ids), self.assertRaises(SafetyError):
                    production._send_episode_search(self.api, ids)
        opener.assert_not_called()


if __name__ == "__main__":
    unittest.main()
