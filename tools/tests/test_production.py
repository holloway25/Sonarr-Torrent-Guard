import copy
import tempfile
import datetime
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import production
from guard import GuardError, run
from safety import SafetyError
from tools.tests.test_guard import FakeApi, manifest


class ProductionTests(unittest.TestCase):
    def setUp(self):
        for name, value in (("wait_for_event_boundary", None), ("event_boundary_reached", True)):
            boundary = patch("production." + name, return_value=value)
            boundary.start()
            self.addCleanup(boundary.stop)
        connectivity = patch("production.require_connectivity", return_value={"status": "verified"})
        connectivity.start()
        self.addCleanup(connectivity.stop)
        self.hash = "a" * 40
        self.config = {"dry_run": False, "qbittorrent": {"url": "https://downloader.example.invalid"},
                       "sonarr": {"HD": {"url": "https://sonarr.example.invalid", "api_key": "REPLACE_ME",
                           "category": "tv-hd", "download_client_binding": {
                               "id": 1, "endpoint": "https://downloader.example.invalid"},
                           "indexers": {"public": ["Public Source"], "private": ["Private Source"]}}}}
        client = {"id": 1, "name": "Downloader", "implementation": "QBittorrent", "enable": True,
                  "fields": [{"name": k, "value": v} for k, v in {
                      "host": "downloader.example.invalid", "port": 443, "useSsl": True,
                      "urlBase": "", "tvCategory": "tv-hd"}.items()]}
        self.grab = {"id": 5, "eventType": "grabbed", "downloadId": self.hash.upper(),
                     "seriesId": 2, "episodeId": 3, "sourceTitle": "Example Show S01E01",
                     "data": {"indexer": "Public Source", "downloadClientName": "Downloader"}}
        added = int(time.time()) - 600
        self.grab["date"] = datetime.datetime.fromtimestamp(added, datetime.timezone.utc).isoformat()
        self.s = FakeApi({
            "/api/v3/queue": {"totalRecords": 1, "records": [{"id": 7, "downloadId": self.hash.upper(),
                                "seriesId": 2, "episodeId": 3, "downloadClientId": 1}]},
            "/api/v3/history": {"totalRecords": 1, "records": [self.grab]},
            "/api/v3/history/since": [self.grab], "/api/v3/blocklist": {"totalRecords": 0, "records": []},
            "/api/v3/downloadclient": [client], "/api/v3/system/status": {"version": "4.0.20.3014"},
            "/api/v3/config/downloadclient": {"autoRedownloadFailed": True, "autoRedownloadFailedFromInteractiveSearch": True}})
        self.s.config, self.s.deadline = self.config["sonarr"]["HD"], None
        self.qb = FakeApi({"/api/v2/torrents/info": [{"hash": self.hash, "category": "tv-hd",
                                                   "state": "stoppedUP", "added_on": added}],
                           "/api/v2/torrents/files": manifest(("episode.exe", 0))})
        self.apis = {"HD": self.s}
        self.report = run(self.config, self.qb, self.apis)[0]
        self.folder = tempfile.TemporaryDirectory()
        self.lock_path = Path(self.folder.name) / "guard.lock"
        self.context = self.capture(self.report)

    def tearDown(self):
        self.folder.cleanup()

    def capture(self, report):
        rows = self.s.routes["/api/v3/queue"]["records"]
        queue_rows = [[row["id"], row["episodeId"], row["downloadId"].lower()]
                      for row in rows if row["id"] in report["queue_ids"]]
        return production.capture_context(self.config, self.s, dict(report, queue_rows=queue_rows))

    def results(self):
        stamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.qb.routes["/api/v2/torrents/info"] = []
        failed = dict(self.grab, id=6, eventType="downloadFailed", date=stamp)
        replacement = dict(self.grab, id=8, downloadId="b" * 40, date=stamp)
        self.s.routes["/api/v3/history/since"] = [self.grab, failed, replacement]
        block = {"id": 9, "seriesId": 2, "episodeIds": [3], "indexer": "Public Source", "protocol": "torrent",
                 "sourceTitle": self.grab["sourceTitle"], "date": stamp}
        self.s.routes["/api/v3/blocklist"] = {"totalRecords": 1, "records": [block]}

    def observe(self):
        return production.OutcomeVerifier(self.config, self.qb, self.apis, self.context).observe()

    def hybrid_report(self, *, blocklist_evidence=False):
        v1 = "b" * 40
        v2 = self.hash + "c" * 24
        self.qb.routes["/api/v2/torrents/properties"] = {
            "hash": self.hash, "infohash_v1": v1, "infohash_v2": v2}
        self.grab["downloadId"] = v1.upper()
        if blocklist_evidence:
            date = datetime.datetime.fromisoformat(self.grab["date"]) + datetime.timedelta(seconds=1)
            canonical = dict(self.grab, id=6, date=date.isoformat(), downloadId=self.hash.upper())
            self.s.routes["/api/v3/history"] = {"records": [canonical, self.grab], "totalRecords": 2}
        report = run(self.config, self.qb, self.apis)[0]
        self.assertEqual(report["decision"], "would_fail")
        return report

    def test_hybrid_private_source_and_newer_private_grab_are_protected(self):
        self.hybrid_report()
        self.grab["data"]["indexer"] = "Private Source"
        self.assertEqual(run(self.config, self.qb, self.apis)[0]["reason"], "private_source_protected")
        self.grab["data"]["indexer"] = "Public Source"
        later = datetime.datetime.fromisoformat(self.grab["date"]) + datetime.timedelta(seconds=1)
        private = dict(self.grab, id=6, downloadId=self.hash, date=later.isoformat(),
                       data={**self.grab["data"], "indexer": "Private Source"})
        self.s.routes["/api/v3/history"] = {"records": [private, self.grab], "totalRecords": 2}
        self.assertEqual(run(self.config, self.qb, self.apis)[0]["reason"], "private_source_protected")

    def test_history_from_other_downloader_cannot_override_bound_private_grab(self):
        private = dict(self.grab, data={**self.grab["data"], "indexer": "Private Source"})
        later = datetime.datetime.fromisoformat(self.grab["date"]) + datetime.timedelta(seconds=1)
        for client_name in ("Other Downloader", None, 123):
            with self.subTest(client_name=client_name):
                other = dict(self.grab, id=6, date=later.isoformat(), data={**self.grab["data"],
                             "downloadClientName": client_name})
                self.s.routes["/api/v3/history"] = {"records": [other, private], "totalRecords": 2}
                self.qb.calls.clear()
                report = run(self.config, self.qb, self.apis)[0]
                self.assertEqual(report["decision"], "skip")
                self.assertEqual(report["reason"], "unconfirmed_grab_download_client")
                self.assertFalse(any(route.endswith("/files") for route, _ in self.qb.calls))

    def test_private_indexer_on_any_matching_queue_row_vetoes_public_history(self):
        queue = self.s.routes["/api/v3/queue"]
        extra = dict(queue["records"][0], id=8)
        queue["records"].append(extra)
        queue["totalRecords"] = 2
        for source in ("Private Source", "PRIVATE SOURCE", "  Private Source  "):
            with self.subTest(source=source):
                extra["indexer"] = source
                self.qb.calls.clear()
                report = run(self.config, self.qb, self.apis)[0]
                self.assertEqual(report["decision"], "skip")
                self.assertEqual(report["reason"], "private_queue_source_protected")
                self.assertFalse(any(route.endswith("/files") for route, _ in self.qb.calls))

    def test_explicit_queue_source_conflicts_hold_even_when_history_is_public(self):
        queue = self.s.routes["/api/v3/queue"]["records"][0]
        for mode in ("public_allowlist", "private_exclusions"):
            self.config["sonarr"]["HD"]["indexers"]["mode"] = mode
            for source, expected in ((None, "would_fail"), ("", "would_fail"),
                                     ("Public Source", "would_fail"), ("Other Source", "skip"),
                                     (False, "skip")):
                with self.subTest(mode=mode, source=source):
                    queue["indexer"] = source
                    report = run(self.config, self.qb, self.apis)[0]
                    self.assertEqual(report["decision"], expected)
                    if expected == "skip":
                        self.assertEqual(report["reason"], "conflicting_queue_source_protected")

    def test_hash_only_torrent_properties_cannot_verify_identity(self):
        self.qb.routes["/api/v2/torrents/properties"] = {"hash": self.hash}
        self.qb.calls.clear()
        report = run(self.config, self.qb, self.apis)[0]
        self.assertEqual(report["decision"], "skip")
        self.assertEqual(report["reason"], "torrent_hash_identity_unavailable")
        self.assertFalse(any(route.endswith("/files") for route, _ in self.qb.calls))

    def test_hybrid_history_is_case_independent_and_bounded_to_the_grab(self):
        self.hybrid_report()
        lower = dict(self.grab, downloadId="b" * 40)
        old_date = datetime.datetime.fromtimestamp(
            self.report["download_added_on"] - 121, datetime.timezone.utc).isoformat()
        old = dict(self.grab, id=2, date=old_date)
        original_call = self.s.call

        def call(route, params=None):
            if route != "/api/v3/history":
                return original_call(route, params)
            self.assertEqual(params["episodeId"], self.grab["episodeId"])
            self.assertEqual(params["seriesIds"], self.grab["seriesId"])
            self.assertEqual(params["page"], 1)
            self.assertNotIn("downloadId", params)
            earlier = [dict(old, id=100 + n) for n in range(99)]
            return {"records": [lower, *earlier], "totalRecords": 201}

        with patch.object(self.s, "call", side_effect=call):
            report = run(self.config, self.qb, self.apis)[0]
        self.assertEqual(report["decision"], "would_fail")
        self.assertEqual(report["grab_ids"], [self.grab["id"]])

    def test_hybrid_same_instance_secondary_queue_group_blocks_proposal(self):
        self.hybrid_report()
        queue = self.s.routes["/api/v3/queue"]
        queue["records"].append(dict(queue["records"][0], id=8, episodeId=4, downloadId="b" * 40))
        queue["totalRecords"] = 2
        self.qb.calls.clear()
        reports = run(self.config, self.qb, self.apis)
        canonical = next(report for report in reports if report["hash"] == self.hash)
        self.assertEqual(canonical["reason"], "ambiguous_alias_queue_ownership")
        self.assertFalse(any(report["decision"] == "would_fail" for report in reports))
        self.assertFalse(any(route.endswith("/files") for route, _ in self.qb.calls))

    def test_hybrid_other_instance_owner_blocks_cleanup(self):
        self.hybrid_report()
        other = copy.deepcopy(self.s)
        other.routes["/api/v3/queue"]["records"][0]["downloadId"] = "b" * 40
        other.routes["/api/v3/queue"]["records"][0]["id"] = 8
        config = copy.deepcopy(self.config)
        config["sonarr"]["UHD"] = copy.deepcopy(config["sonarr"]["HD"])
        reports = run(config, self.qb, {"HD": self.s, "UHD": other})
        hd = next(r for r in reports if r["instance"] == "HD")
        self.assertEqual(hd["reason"], "ambiguous_instance_ownership")

    def test_hybrid_invalid_or_colliding_identity_never_assesses_files(self):
        self.hybrid_report()
        original = copy.deepcopy(self.qb.routes["/api/v2/torrents/properties"])
        for field, value in (("hash", "d" * 40), ("infohash_v1", 123),
                             ("infohash_v2", "c" * 40), ("infohash_v1", "0" * 40)):
            with self.subTest(field=field):
                self.qb.routes["/api/v2/torrents/properties"] = {**original, field: value}
                self.qb.calls.clear()
                self.assertEqual(run(self.config, self.qb, self.apis)[0]["decision"], "skip")
                self.assertFalse(any(route.endswith("/files") for route, _ in self.qb.calls))
        self.qb.routes["/api/v2/torrents/properties"] = original
        self.qb.routes["/api/v2/torrents/info"].append({
            **self.qb.routes["/api/v2/torrents/info"][0], "hash": "b" * 40})
        report = run(self.config, self.qb, self.apis)[0]
        self.assertEqual(report["reason"], "ambiguous_torrent_hash_identity")

    def test_a_second_torrent_cannot_claim_the_candidates_primary_or_alternate_hash(self):
        torrents = self.qb.routes["/api/v2/torrents/info"]
        original = torrents[0]
        other = "d" * 40
        other_torrent = dict(original, hash=other, infohash_v1=self.hash, infohash_v2=other + "e" * 24)
        for hybrid in (False, True):
            with self.subTest(hybrid=hybrid):
                torrents[:] = [original]
                if hybrid:
                    self.hybrid_report()
                    other_torrent["infohash_v1"] = "b" * 40
                torrents.append(other_torrent)
                self.qb.calls.clear()
                report = run(self.config, self.qb, self.apis)[0]
                self.assertEqual(report["decision"], "skip")
                self.assertEqual(report["reason"], "ambiguous_torrent_hash_identity")
                self.assertFalse(any(route.endswith("/files") for route, _ in self.qb.calls))

    def digit_hash_report(self):
        self.hash = "1" * 40
        self.grab["downloadId"] = self.hash
        self.s.routes["/api/v3/queue"]["records"][0]["downloadId"] = self.hash
        self.qb.routes["/api/v2/torrents/info"][0]["hash"] = self.hash
        report = run(self.config, self.qb, self.apis)[0]
        self.assertEqual(report["decision"], "would_fail")
        return report

    def test_assessment_rejects_numeric_history_download_id(self):
        self.digit_hash_report()
        self.grab["downloadId"] = int(self.hash)
        report = run(self.config, self.qb, self.apis)[0]
        self.assertEqual(report["decision"], "skip")
        self.assertEqual(report["reason"], "invalid_history_download_id")

    def test_newer_private_grab_never_falls_back_to_older_public_grab(self):
        self.digit_hash_report()
        later = datetime.datetime.fromisoformat(self.grab["date"]) + datetime.timedelta(seconds=1)
        private = dict(self.grab, id=self.grab["id"] + 1, date=later.isoformat(),
                       data={**self.grab["data"], "indexer": "Private Source"})
        self.s.routes["/api/v3/history"] = {"totalRecords": 2, "records": [self.grab, private]}
        for download_id, reason in ((self.hash, "private_source_protected"),
                                    (int(self.hash), "invalid_history_download_id")):
            with self.subTest(download_id=download_id):
                private["downloadId"] = download_id
                report = run(self.config, self.qb, self.apis)[0]
                self.assertEqual(report["decision"], "skip")
                self.assertEqual(report["reason"], reason)

    def conflicting_grab_order(self):
        later_private = dict(self.grab, id=self.grab["id"] - 1,
                             data={**self.grab["data"], "indexer": "Private Source"})
        earlier = datetime.datetime.fromisoformat(self.grab["date"]) - datetime.timedelta(seconds=60)
        self.grab["date"] = earlier.isoformat()
        return later_private

    def test_assessment_holds_grabs_with_conflicting_source_order(self):
        private = self.conflicting_grab_order()
        self.s.routes["/api/v3/history"] = {"totalRecords": 2, "records": [self.grab, private]}
        report = run(self.config, self.qb, self.apis)[0]
        self.assertEqual(report["decision"], "skip")
        self.assertEqual(report["reason"], "conflicting_grab_source_order")

    def test_malformed_outcome_event_type_never_confirms_failure_or_replacement(self):
        for index, values in ((1, (True, 4.0, "4", None)), (2, (True, 1.0, "1", None))):
            for value in values:
                with self.subTest(index=index, value=value):
                    self.results()
                    self.s.routes["/api/v3/history/since"][index]["eventType"] = value
                    observed = self.observe()
                    self.assertIsNone(observed["failed"])
                    self.assertIsNone(observed["replacement_observed"])
                    self.assertIs(observed["blocklisted"], True)

    def test_api_results_are_independent_and_data_deletion_remains_unknown(self):
        self.results()
        result = self.observe()
        for field in ("torrent_absent", "failed", "blocklisted", "replacement_observed"):
            self.assertIs(result[field], True)
        self.assertIsNone(result["data_deleted"])

    def test_recovery_history_ignores_more_than_ten_thousand_unrelated_events(self):
        self.results()
        history = self.s.routes["/api/v3/history/since"]
        history.extend(dict(self.grab, id=100 + i, episodeId=99, date=history[1]["date"])
                       for i in range(10001))
        self.s.calls.clear()
        result = self.observe()
        self.assertIs(result["failed"], True)
        self.assertIs(result["replacement_observed"], True)
        calls = [(route, params) for route, params in self.s.calls if route.startswith("/api/v3/history")]
        self.assertEqual(len(calls), 1)
        route, params = calls[0]
        self.assertEqual(route, "/api/v3/history")
        self.assertEqual((params["seriesIds"], params["episodeId"]), (2, 3))

    def test_incomplete_scoped_history_preserves_uncertainty(self):
        self.results()
        history = self.s.routes["/api/v3/history/since"]
        # Even established evidence cannot be confirmed from a partial read.
        history.extend(dict(self.grab, id=100 + i, date=history[1]["date"]) for i in range(100))
        self.config["max_pages"] = 1
        result = self.observe()
        self.assertIsNone(result["failed"])
        self.assertIsNone(result["replacement_observed"])
        self.assertIs(result["torrent_absent"], True)
        self.assertIs(result["blocklisted"], True)

    def test_queue_disappearance_alone_does_not_prove_failure_or_replacement(self):
        self.qb.routes["/api/v2/torrents/info"] = []
        result = self.observe()
        self.assertTrue(result["torrent_absent"])
        for field in ("failed", "blocklisted", "replacement_observed"):
            self.assertFalse(result[field])

    def test_preexisting_records_are_not_mistaken_for_new_results(self):
        self.results()
        self.context["baseline_history_ids"] = [5, 6, 8]
        self.context["baseline_blocklist_ids"] = [9]
        result = self.observe()
        self.assertFalse(result["failed"])
        self.assertFalse(result["blocklisted"])
        self.assertFalse(result["replacement_observed"])

    def test_new_records_before_dispatch_are_not_outcome_evidence(self):
        self.results()
        result = production.OutcomeVerifier(self.config, self.qb, self.apis, self.context,
                                            not_before=time.time()+10).observe()
        for field in ("failed", "blocklisted", "replacement_observed"):
            self.assertFalse(result[field])

    def test_same_second_results_are_uncertain_not_missing_or_confirmed(self):
        self.results()
        stamp = "2026-01-01T00:00:10Z"
        for row in self.s.routes["/api/v3/history/since"][1:]:
            row["date"] = stamp
        self.s.routes["/api/v3/blocklist"]["records"][0]["date"] = stamp
        boundary = production.event_time({"date": stamp}) + .25
        result = production.OutcomeVerifier(self.config, self.qb, self.apis, self.context, boundary).observe()
        for field in ("failed", "blocklisted", "replacement_observed"):
            self.assertIsNone(result[field])

    def test_timestamp_precision_timezone_and_predispatch_boundaries(self):
        boundary = production.event_time({"date": "2026-01-01T00:00:10.25Z"})
        for stamp, expected in (("2026-01-01T00:00:09Z", False),
                                ("2026-01-01T00:00:10Z", None),
                                ("2026-01-01T00:00:10.1Z", False),
                                ("2026-01-01T00:00:10.2Z", None),
                                ("2026-01-01T00:00:10.249Z", False),
                                ("2026-01-01T00:00:10.25Z", True),
                                ("2026-01-01T00:00:11Z", True),
                                ("2026-01-01T11:00:10+11:00", None)):
            with self.subTest(stamp=stamp):
                self.assertIs(production.event_after({"date": stamp}, boundary), expected)

    def test_same_second_baseline_records_still_cannot_confirm_outcomes(self):
        self.results()
        self.context["baseline_history_ids"] = [5, 6, 8]
        self.context["baseline_blocklist_ids"] = [9]
        result = self.observe()
        self.assertFalse(result["failed"])
        self.assertFalse(result["blocklisted"])

    def test_missing_event_timestamps_are_unknown_not_confirmations(self):
        self.results()
        del self.s.routes["/api/v3/history/since"][1]["date"]
        del self.s.routes["/api/v3/blocklist"]["records"][0]["date"]
        result = self.observe()
        self.assertIsNone(result["failed"])
        self.assertIsNone(result["blocklisted"])

    def test_other_episode_hash_title_client_and_indexer_do_not_match(self):
        for mutation in ("episode", "hash", "title", "client", "indexer"):
            self.results()
            if mutation == "episode":
                self.s.routes["/api/v3/history/since"][1]["episodeId"] = 99
            elif mutation == "hash":
                self.s.routes["/api/v3/history/since"][1]["downloadId"] = "c" * 40
            elif mutation == "title":
                self.s.routes["/api/v3/history/since"][1]["sourceTitle"] = "Different release"
            elif mutation == "client":
                self.s.routes["/api/v3/history/since"][1]["data"] = {"downloadClientName": "Other"}
            else:
                self.s.routes["/api/v3/blocklist"]["records"][0]["indexer"] = "Other Source"
            with self.subTest(mutation=mutation):
                self.assertFalse(self.observe()["blocklisted" if mutation == "indexer" else "failed"])

    def test_missing_downloader_identity_differs_from_a_known_different_client(self):
        for data, expected in ((None, None), ({}, None), ({"downloadClientName": " "}, None),
                               ({"downloadClientName": True}, None), ({"downloadClientName": "Other"}, False)):
            with self.subTest(data=data):
                self.results()
                history = self.s.routes["/api/v3/history/since"]
                history[1]["data"] = data
                observed = self.observe()
                self.assertIs(observed["failed"], expected)
                self.assertIs(observed["replacement_observed"], True)
                self.assertIs(observed["blocklisted"], True)

    def test_current_alias_needs_new_attempt_evidence_to_count_as_replacement(self):
        self.results()
        current = {"hash": "b" * 40, "infohash_v1": self.hash, "infohash_v2": "b" * 64,
                   "added_on": self.context["download_added_on"]}
        self.qb.routes["/api/v2/torrents/info"] = [current]
        result = self.observe()
        self.assertIs(result["torrent_absent"], False)
        self.assertIs(result["replacement_observed"], False)

        current["added_on"] = int(time.time()) + 10
        self.s.routes["/api/v3/history/since"][2]["date"] = datetime.datetime.fromtimestamp(
            current["added_on"], datetime.timezone.utc).isoformat()
        result = self.observe()
        self.assertIs(result["torrent_absent"], True)
        self.assertIs(result["replacement_observed"], True)

    def test_failed_qb_alias_lookup_cannot_confirm_a_new_replacement(self):
        self.results()
        alias = "b" * 40
        self.qb.routes["/api/v2/torrents/info"] = [
            {"hash": alias, "infohash_v1": self.hash, "infohash_v2": alias + "c" * 24,
             "added_on": self.context["download_added_on"]}]
        self.assertIs(self.observe()["replacement_observed"], False)
        self.qb.routes["/api/v2/torrents/info"] = TimeoutError()
        observed = self.observe()
        self.assertIsNone(observed["torrent_absent"])
        self.assertIsNone(observed["replacement_observed"])
        self.assertIs(observed["failed"], True)

    def test_qb_outage_leaves_a_new_same_hash_grab_unverified(self):
        self.results()
        added = int(time.time()) + 10
        date = datetime.datetime.fromtimestamp(added, datetime.timezone.utc).isoformat()
        self.qb.routes["/api/v2/torrents/info"] = [
            {"hash": self.hash, "infohash_v1": self.hash, "infohash_v2": "", "added_on": added}]
        self.s.routes["/api/v3/history/since"] = [dict(self.grab, id=20, date=date)]
        self.assertIs(self.observe()["replacement_observed"], True)
        self.qb.routes["/api/v2/torrents/info"] = TimeoutError()
        result = self.observe()
        self.assertIsNone(result["replacement_observed"])
        self.assertIsNone(result["torrent_absent"])

    def test_qb_outage_cannot_exclude_failure_with_a_possible_alias(self):
        self.results()
        self.s.routes["/api/v3/history/since"][1]["downloadId"] = "b" * 40
        self.qb.routes["/api/v2/torrents/info"] = TimeoutError()
        self.assertIsNone(self.observe()["failed"])

    def test_pack_replacement_combines_same_hash_and_different_hash_evidence(self):
        self.results()
        added = int(time.time()) + 10
        date = datetime.datetime.fromtimestamp(added, datetime.timezone.utc).isoformat()
        self.qb.routes["/api/v2/torrents/info"] = [
            {"hash": self.hash, "infohash_v1": self.hash, "infohash_v2": "", "added_on": added}]
        self.s.routes["/api/v3/history/since"] = [
            dict(self.grab, id=20, date=date),
            dict(self.grab, id=21, episodeId=4, downloadId="b" * 40, date=date)]
        context = dict(self.context, episode_ids=[3, 4], queue_rows=[*self.context["queue_rows"], [8, 4, self.hash]])
        observed = production.OutcomeVerifier(self.config, self.qb, self.apis, context).observe()
        self.assertIs(observed["replacement_observed"], True)
        self.assertIsNone(observed["torrent_absent"])

    def test_usenet_blocklist_cannot_confirm_torrent_cleanup(self):
        self.results()
        block = self.s.routes["/api/v3/blocklist"]["records"][0]
        for protocol, expected in (("usenet", False), (1, False), ("torrent", True), (2, True),
                                   ("unknown", None), (None, None), (True, None)):
            with self.subTest(protocol=protocol):
                block["protocol"] = protocol
                self.assertIs(self.observe()["blocklisted"], expected)
        block.update(id=0, protocol="torrent")
        self.assertIsNone(self.observe()["blocklisted"])

    def test_blocklist_baseline_window_skips_old_pages_and_retains_recent_limit(self):
        count = 2001
        recent = datetime.datetime.now(datetime.timezone.utc).isoformat()
        rows = [{"id": i + 1, "seriesId": 2, "date": "2020-01-01T00:00:00Z"}
                for i in range(count)]
        rows[0]["date"] = recent
        call = self.s.call

        def paginated(route, params=None):
            if route != "/api/v3/blocklist":
                return call(route, params)
            page = params["page"]
            self.assertEqual((params.get("sortKey"), params.get("sortDirection")), ("date", "descending"))
            return {"records": rows[(page - 1) * 100:page * 100], "totalRecords": count}

        with patch.object(self.s, "call", side_effect=paginated) as wrapped:
            context = self.capture(self.report)
            self.assertEqual(context["baseline_blocklist_ids"], [1])
            self.assertEqual([c.args[1]["page"] for c in wrapped.call_args_list
                              if c.args[0] == "/api/v3/blocklist"], [1])
            for row in rows:
                row["date"] = recent
            wrapped.reset_mock()
            with self.assertRaisesRegex(GuardError, "^pagination_limit_reached$"):
                self.capture(self.report)
            self.assertEqual(sum(c.args[0] == "/api/v3/blocklist" for c in wrapped.call_args_list), 20)
            for row in rows:
                row["seriesId"] = 99
            wrapped.reset_mock()
            with self.assertRaisesRegex(GuardError, "^sonarr_unscoped_blocklist_limit_reached$"):
                self.capture(self.report)
            self.assertEqual(sum(c.args[0] == "/api/v3/blocklist" for c in wrapped.call_args_list), 20)

    def test_partial_outage_does_not_erase_other_verified_results(self):
        self.results()
        self.s.routes["/api/v3/history/since"] = TimeoutError()
        result = self.observe()
        self.assertTrue(result["torrent_absent"])
        self.assertTrue(result["blocklisted"])
        self.assertIsNone(result["failed"])
        self.assertIsNone(result["replacement_observed"])

    def test_malformed_torrent_response_never_proves_absence(self):
        self.qb.routes["/api/v2/torrents/info"] = [{}]
        self.assertIsNone(self.observe()["torrent_absent"])

    def test_context_has_no_raw_release_title_endpoint_or_credentials(self):
        text = str(self.context)
        for value in (self.grab["sourceTitle"], "example.invalid", "REPLACE_ME"):
            self.assertNotIn(value, text)
        with self.assertRaises(SafetyError):
            production.validate_context(dict(self.context, password="not allowed"))

    def test_context_title_comes_from_current_grab_not_older_same_hash(self):
        date = datetime.datetime.fromisoformat(self.grab["date"]) - datetime.timedelta(seconds=1)
        old = dict(self.grab, id=4, date=date.isoformat(), sourceTitle="An older display title")
        self.s.routes["/api/v3/history"] = {"totalRecords": 2, "records": [old, self.grab]}
        context = self.capture(self.report)
        self.assertEqual(context["release_title_digest"], production.digest(self.grab["sourceTitle"]))

    def test_endpoint_drift_and_unreviewed_version_stop_observation(self):
        self.s.routes["/api/v3/system/status"]["version"] = "unreviewed"
        with self.assertRaises(SafetyError):
            self.observe()
        self.s.routes["/api/v3/system/status"]["version"] = "4.0.20.3014"
        self.config["qbittorrent"]["url"] = "https://other.example.invalid"
        with self.assertRaises(SafetyError):
            self.observe()

    def test_sender_refuses_production_transport_when_release_gate_is_off(self):
        with patch("urllib.request.build_opener") as opener:
            with self.assertRaisesRegex(SafetyError, "live_execution_disabled"):
                production._send_queue_delete(self.s, 7, blocklist=True)
            opener.assert_not_called()

    def test_delete_transport_has_fixed_scope_and_never_follows_redirects(self):
        response = Mock(status=200)
        response.read.return_value = b""
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        opener = Mock()
        opener.open.return_value = response
        with patch("production.ROUTINE_RELEASE_ENABLED", True), patch("urllib.request.build_opener", return_value=opener):
            production._send_queue_delete(self.s, 7, blocklist=True)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.get_method(), "DELETE")
        self.assertIn("/api/v3/queue/7?", request.full_url)
        for param in ("removeFromClient=true", "blocklist=true", "skipRedownload=false", "changeCategory=false"):
            self.assertIn(param, request.full_url)
        with self.assertRaises(SafetyError):
            production.RejectDeleteRedirect().redirect_request(None)


    def test_single_hash_history_checks_newer_private_grab_regardless_of_case(self):
        more_recent = datetime.datetime.fromtimestamp(
            self.report["download_added_on"] + 5, datetime.timezone.utc).isoformat()
        private = dict(self.grab, id=6, downloadId=self.hash.lower(), date=more_recent,
                       data={**self.grab["data"], "indexer": "Private Source"})
        original = self.s.call

        def case_sensitive_history(route, params=None):
            if route != "/api/v3/history":
                return original(route, params)
            self.assertEqual(params.get("episodeId"), self.grab["episodeId"])
            self.assertEqual(params.get("seriesIds"), self.grab["seriesId"])
            rows = [private, self.grab]
            if params.get("downloadId"):
                rows = [row for row in rows if row["downloadId"] == params["downloadId"]]
            return {"records": rows, "totalRecords": len(rows)}

        with patch.object(self.s, "call", side_effect=case_sensitive_history):
            report = run(self.config, self.qb, self.apis)[0]
            with self.assertRaisesRegex(SafetyError, "identity_or_manifest_changed"):
                self.capture(self.report)
        self.assertEqual(report["decision"], "skip")
        self.assertEqual(report["reason"], "private_source_protected")


    def test_hybrid_recovery_uses_bulk_info_and_holds_on_incomplete_evidence(self):
        report = self.hybrid_report(blocklist_evidence=True)
        self.context = self.capture(report)
        self.results()
        listed = [{"hash": format(n, "040x"), "infohash_v1": format(n, "040x"),
                   "infohash_v2": ""} for n in range(1, 201)]
        self.qb.routes["/api/v2/torrents/info"] = listed
        self.qb.calls.clear()
        self.assertIs(self.observe()["torrent_absent"], True)
        self.assertEqual([route for route, _ in self.qb.calls], ["/api/v2/torrents/info"])
        listed.append({"hash": "d" * 40, "infohash_v1": "b" * 40,
                       "infohash_v2": "d" * 64, "added_on": report["download_added_on"]})
        self.assertIs(self.observe()["torrent_absent"], False)
        del listed[-1]["infohash_v2"]
        self.assertIsNone(self.observe()["torrent_absent"])


    def test_hybrid_outcome_uses_alias_for_failure_not_replacement(self):
        report = self.hybrid_report(blocklist_evidence=True)
        self.context = self.capture(report)
        self.results()
        self.s.routes["/api/v3/history/since"][2]["downloadId"] = self.hash + "c" * 24
        outcome = self.observe()
        self.assertIs(outcome["failed"], True)
        self.assertIs(outcome["torrent_absent"], True)
        self.assertIs(outcome["replacement_observed"], False)


    def test_numeric_history_download_id_cannot_confirm_outcomes(self):
        report = self.digit_hash_report()
        self.context = self.capture(report)
        self.results()
        history = self.s.routes["/api/v3/history/since"]
        history[2]["downloadId"] = "2" * 40
        self.assertIs(self.observe()["replacement_observed"], True)
        history[2]["downloadId"] = int("2" * 40)
        history[1]["downloadId"] = int(self.hash)
        observed = self.observe()
        self.assertIs(observed["replacement_observed"], False)
        self.assertIsNone(observed["failed"])
        self.assertIs(observed["blocklisted"], True)


class FileCleanupTests(unittest.TestCase):
    def setUp(self):
        self.f = ProductionTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.addCleanup(self.f.tearDown)

    def container_cycle(self, folder, send, *, mode="live"):
        from contextlib import redirect_stdout
        from io import StringIO
        import json
        import os
        import container_worker
        import routine

        f = self.f
        f.qb.login = Mock()
        config = dict(f.config, dry_run=True)
        config["qbittorrent"].update(username="downloader", password="REPLACE_ME")
        path = folder / "connections.json"
        with patch.object(container_worker, "CONFIG_DIR", folder):
            if not path.exists():
                container_worker.atomic_json(path, config)
                container_worker.atomic_json(folder / container_worker.CONTAINER_SCOPE_FILE,
                                             container_worker.container_scope_record(config))
        args = ["routine.py", "--config", str(path), "--container-mode",
                "--live", "--log-file", str(folder / "routine.log")]
        adapters = [f.qb, *f.apis.values()]
        with patch("sys.argv", args), patch.dict(os.environ, {"STGUARD_MODE": mode}), patch(
                "routine.Api", side_effect=adapters), patch("public.require_connectivity"), patch(
                "urllib.request.build_opener", return_value=Mock(open=send)), redirect_stdout(StringIO()) as output:
            self.assertEqual(routine.main(), 0)
        return json.loads(output.getvalue())

    def sonarr_transport(self, request, **kwargs):
        from urllib.parse import parse_qs, urlsplit

        url = urlsplit(request.full_url)
        self.assertEqual(url.netloc, "sonarr.example.invalid")
        self.assertEqual(request.get_method(), "DELETE")
        self.assertEqual(url.path, "/api/v3/queue/7")
        self.assertEqual(parse_qs(url.query), {"removeFromClient": ["true"], "blocklist": ["true"],
                                              "skipRedownload": ["false"], "changeCategory": ["false"]})
        self.f.qb.routes["/api/v2/torrents/info"] = []
        response = Mock(status=200, read=Mock(return_value=b""))
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        return response

    def test_live_container_uses_the_native_remove_and_blocklist_action_for_each_file_failure(self):
        f = self.f
        torrents = f.qb.routes["/api/v2/torrents/info"]
        cases = [
            (manifest(("episode.mkv", 1), ("PAYLOAD.EXE", 0)), "contains_exe"),
            (manifest(("episode.mkv", 1), ("payload.scr", 0)), "contains_scr"),
            (manifest(("episode.mkv", 1), ("archive.RAR", 1)), "blocked_file_selected"),
            (manifest(("episode.mkv", 0)), "all_files_unselected"),
            (manifest(("info.nfo", 1), ("notes.txt", 1), ("padding", 0)), "only_txt_nfo_selected"),
        ]
        for files, reason in cases:
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as folder, patch(
                    "production.METADATA_RETRY_RELEASE_ENABLED", False):
                f.qb.routes["/api/v2/torrents/info"] = torrents
                f.qb.routes["/api/v2/torrents/files"] = files
                send = Mock(side_effect=self.sonarr_transport)
                result = self.container_cycle(Path(folder), send)
                self.assertEqual(result["status"], "completed")
                self.assertIn(reason, result["assessment"][0]["reasons"])
                self.assertEqual(len(result["actions"]), 1)
                action, = result["actions"]
                self.assertEqual(action["stage"], "sonarr_remove_blocklist_accepted")

                send.assert_called_once()

    def test_live_container_rejects_healthy_private_ambiguous_and_dry_run_candidates(self):
        f = self.f
        row = f.s.routes["/api/v3/queue"]["records"][0]
        for case in ("healthy", "private", "ambiguous", "dry-run"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as folder:
                f.qb.routes["/api/v2/torrents/files"] = (
                    manifest(("episode.mkv", 1), ("extras.rar", 0), ("link.lnk", 0))
                    if case == "healthy" else manifest(("bad.scr", 0)))
                row["indexer"] = "Private Source" if case == "private" else "Public Source"
                f.config["sonarr"].pop("UHD", None)
                f.apis.pop("UHD", None)
                if case == "ambiguous":
                    from copy import deepcopy
                    other = FakeApi(deepcopy(f.s.routes))
                    other.config = dict(f.s.config, url="https://other.example.invalid", category="tv-uhd")
                    f.config["sonarr"]["UHD"] = other.config
                    f.apis["UHD"] = other
                send = Mock()
                result = self.container_cycle(Path(folder), send, mode="dry-run" if case == "dry-run" else "live")
                self.assertEqual(result["actions"], [])
                if case != "dry-run":
                    self.assertEqual(result["status"], "completed")
                    if case == "ambiguous":
                        self.assertIn("ambiguous_instance_ownership", {r.get("reason") for r in result["assessment"]})
                send.assert_not_called()

    def test_file_removal_does_not_read_sonarr_blocklist_or_retry_settings(self):
        f = self.f
        f.s.routes["/api/v3/config/downloadclient"]["autoRedownloadFailed"] = False
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            f.s.calls.clear()
            send = Mock(side_effect=self.sonarr_transport)
            result = self.container_cycle(folder, send)
        action, = result["actions"]
        self.assertEqual(action["stage"], "sonarr_remove_blocklist_accepted")
        self.assertNotIn("/api/v3/blocklist", {route for route, _ in f.s.calls})
        self.assertNotIn("/api/v3/config/downloadclient", {route for route, _ in f.s.calls})
        send.assert_called_once()

    def make_metadata_timeout(self):
        f = self.f
        torrent = f.qb.routes["/api/v2/torrents/info"][0]
        torrent.update(state="metaDL", added_on=int(time.time()) - 2000, total_size=-1, progress=0)
        f.grab["date"] = datetime.datetime.fromtimestamp(torrent["added_on"], datetime.timezone.utc).isoformat()
        f.qb.routes["/api/v2/torrents/files"] = []

    def test_metadata_timeout_removes_without_blocklisting_and_searches_once(self):
        import json
        from urllib.parse import parse_qs, urlsplit

        f = self.f
        self.make_metadata_timeout()
        def transport(request, **kwargs):
            url = urlsplit(request.full_url)
            if request.get_method() == "DELETE":
                self.assertEqual(url.path, "/api/v3/queue/7")
                self.assertEqual(parse_qs(url.query), {"removeFromClient": ["true"], "blocklist": ["false"],
                                                      "skipRedownload": ["true"], "changeCategory": ["false"]})
                f.qb.routes["/api/v2/torrents/info"] = []
                body = b""
            else:
                self.assertEqual(request.get_method(), "POST")
                self.assertEqual(url.path, "/api/v3/command")
                self.assertEqual(json.loads(request.data), {"name": "EpisodeSearch", "episodeIds": [3]})
                body = b'{"id":42,"name":"EpisodeSearch","body":{"episodeIds":[3]}}'
            response = Mock(status=200, read=Mock(return_value=body))
            response.__enter__ = Mock(return_value=response)
            response.__exit__ = Mock(return_value=False)
            return response

        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            send = Mock(side_effect=transport)
            result = self.container_cycle(folder, send)

            self.assertEqual(self.container_cycle(folder, send)["actions"], [])
        action, = result["actions"]
        self.assertEqual((action["stage"], action["search_command_id"]), ("retry_requested", 42))
        self.assertEqual([call.args[0].get_method() for call in send.call_args_list], ["DELETE", "POST"])

    def test_later_cycle_never_replays_a_search_after_unverified_removal(self):
        f = self.f
        self.make_metadata_timeout()

        def accepted(api, queue_id, *, blocklist):
            self.assertIs(blocklist, False)
            f.qb.routes["/api/v2/torrents/info"] = []

        with tempfile.TemporaryDirectory() as folder, patch(
                "production._send_queue_delete", side_effect=accepted) as remove, patch(
                "production._send_episode_search") as search:
            with patch.object(production.OutcomeVerifier, "observe", side_effect=SafetyError("service_unavailable")):
                result = self.container_cycle(Path(folder), Mock())
            action, = result["actions"]
            self.assertEqual(action["stage"], "retry_removal_unverified")
            self.assertEqual(self.container_cycle(Path(folder), Mock())["actions"], [])
        remove.assert_called_once()
        search.assert_not_called()

    def test_new_stateless_metadata_pass_keeps_a_pre_removal_replacement_veto(self):
        f = self.f
        self.make_metadata_timeout()
        stamp = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=5)
        replacement = dict(f.grab, id=20, downloadId="b" * 40, date=stamp.isoformat())
        f.s.routes["/api/v3/history/since"] = [f.grab, replacement]

        def sent(api, queue_id, *, blocklist):
            self.assertIs(blocklist, False)
            f.qb.routes["/api/v2/torrents/info"] = []
            f.s.routes["/api/v3/history/since"] = [f.grab]

        with tempfile.TemporaryDirectory() as folder, patch("production._send_queue_delete", side_effect=sent) as remove, patch(
                "production._send_episode_search") as search:
            result = self.container_cycle(Path(folder), Mock())
        action, = result["actions"]
        self.assertIs(action["torrent_absent"], True)
        self.assertEqual(action["stop_reason"], "replacement_already_grabbed")
        remove.assert_called_once()
        search.assert_not_called()

    def test_public_dry_run_logs_would_remove_and_sends_nothing(self):
        import json
        from contextlib import redirect_stdout
        from io import StringIO
        import public

        f = self.f
        f.qb.login = Mock()
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            path = folder / "dry-run.log"
            args = ["public.py", "--config", str(folder / "connections.json"), "--log-file", str(path)]
            with patch("sys.argv", args), patch("public.load_config", return_value=f.config), patch(
                    "public.Api", side_effect=[f.qb, f.s]), patch("public.require_connectivity"), patch(
                    "urllib.request.build_opener") as transport, redirect_stdout(StringIO()):
                self.assertEqual(public.main(), 0)
            entry, = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual((entry["event"], entry["hash"]), ("would_remove", f.hash))
            self.assertIn("contains_exe", entry["reasons"])
            self.assertIn("time", entry)

            transport.assert_not_called()

    def test_file_removal_with_lost_response_retries_on_next_pass_only_if_still_queued(self):
        f = self.f
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            send = Mock(side_effect=TimeoutError)
            first = self.container_cycle(folder, send)
            action, = first["actions"]
            self.assertEqual(action["stage"], "uncertain")
            send.side_effect = self.sonarr_transport
            second = self.container_cycle(folder, send)
            self.assertEqual(second["actions"][0]["stage"], "sonarr_remove_blocklist_accepted")
            third = self.container_cycle(folder, send)
            self.assertEqual(third["actions"], [])

        self.assertEqual([call.args[0].get_method() for call in send.call_args_list], ["DELETE", "DELETE"])

    def test_live_container_removes_a_new_bad_grab_from_another_public_indexer(self):
        f = self.f
        torrent = f.qb.routes["/api/v2/torrents/info"][0]
        f.config["sonarr"]["HD"]["indexers"]["public"].append("Second Public Source")
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            send = Mock(side_effect=self.sonarr_transport)
            first = self.container_cycle(folder, send)
            action, = first["actions"]
            self.assertEqual(action["stage"], "sonarr_remove_blocklist_accepted")
            added = int(time.time()) + 3
            latest = dict(f.grab, id=50, date=datetime.datetime.fromtimestamp(added, datetime.timezone.utc).isoformat(),
                          data={**f.grab["data"], "indexer": "Second Public Source"})
            f.s.routes["/api/v3/history"] = {"totalRecords": 2, "records": [f.grab, latest]}
            f.s.routes["/api/v3/history/since"] = [f.grab, latest]
            f.qb.routes["/api/v2/torrents/info"] = [dict(torrent, added_on=added)]
            with patch("time.time", return_value=added + 200):
                second = self.container_cycle(folder, send)
        action, = second["actions"]
        self.assertEqual(action["stage"], "sonarr_remove_blocklist_accepted")
        self.assertEqual([call.args[0].get_method() for call in send.call_args_list], ["DELETE", "DELETE"])

    def test_file_manifest_changes_during_final_sonarr_read_hold_removal(self):
        f = self.f
        check = production.check_visible_native_grabs

        def replace_manifest(*args):
            check(*args)
            f.qb.routes["/api/v2/torrents/files"] = manifest(("episode.mkv", 1))

        with tempfile.TemporaryDirectory() as folder, patch(
                "production.check_visible_native_grabs", side_effect=replace_manifest):
            send = Mock()
            result = self.container_cycle(Path(folder), send)
        action, = result["actions"]
        self.assertEqual((action["stage"], action["stop_reason"]), ("held", "identity_or_manifest_changed"))
        send.assert_not_called()

    def test_native_blocklist_holds_conflicting_visible_history(self):
        f = self.f
        hidden_from_episode_query = dict(f.grab, id=6, episodeId=444,
                                         data={**f.grab["data"], "indexer": "Private Source"})
        original = f.s.call

        def history(route, params=None):
            if route == "/api/v3/history" and params and "downloadId" in params:
                return {"totalRecords": 2, "records": [f.grab, hidden_from_episode_query]}
            return original(route, params)

        with tempfile.TemporaryDirectory() as folder, patch.object(f.s, "call", side_effect=history):
            send = Mock()
            result = self.container_cycle(Path(folder), send)
        action, = result["actions"]
        self.assertEqual(action["stop_reason"], "sonarr_blocklist_scope_unverified")
        send.assert_not_called()

    def test_pack_with_conflicting_titles_is_held_but_consistent_titles_still_allow_removal(self):
        f = self.f
        queue = f.s.routes["/api/v3/queue"]
        queue["records"].append(dict(queue["records"][0], id=8, episodeId=4))
        queue["totalRecords"] = 2
        history = f.s.routes["/api/v3/history"]
        second_grab = dict(f.grab, id=6, episodeId=4, sourceTitle="Conflicting Example Title")
        history.update(totalRecords=2, records=[f.grab, second_grab])
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            send = Mock(side_effect=self.sonarr_transport)
            action, = self.container_cycle(folder, send)["actions"]
            self.assertEqual(action["stop_reason"], "ambiguous_release_title_evidence")
            send.assert_not_called()
            second_grab["sourceTitle"] = f.grab["sourceTitle"]
            action, = self.container_cycle(folder, send)["actions"]
            self.assertEqual(action["stage"], "sonarr_remove_blocklist_accepted")
            send.assert_called_once()

    def test_native_cleanup_holds_if_the_file_scope_changes_during_recheck(self):
        import json

        check = production.check_visible_native_grabs
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)

            def protect_source(*args):
                check(*args)
                path = folder / "connections.json"
                config = json.loads(path.read_text())
                config["sonarr"]["HD"]["indexers"] = {
                    "public": [], "private": ["Private Source", "Public Source"],
                }
                path.write_text(json.dumps(config))

            send = Mock()
            with patch("production.check_visible_native_grabs", side_effect=protect_source):
                result = self.container_cycle(folder, send)
        self.assertEqual(result["actions"][0]["stop_reason"], "container_live_scope_confirmation_required")
        send.assert_not_called()

    def test_preflight_verifies_file_policy_removal_read_only(self):
        from contextlib import redirect_stdout
        from io import StringIO
        import json

        f = self.f
        f.qb.login = Mock()
        args = ["production.py", "--config", "connections.json", "--preflight", "HD", f.hash]
        with patch("sys.argv", args), patch("production.load_config", return_value=f.config), patch(
                "production.Api", side_effect=[f.qb, f.s]), patch(
                "production.capture_context", wraps=production.capture_context) as capture, redirect_stdout(StringIO()) as output:
            self.assertEqual(production.main(), 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result["preflight"], "verified")
        self.assertIs(result["live_sender_enabled"], False)
        self.assertEqual(result["operation"], "sonarr_remove_and_blocklist")
        capture.assert_not_called()

    def test_transport_blocks_file_action_when_only_metadata_is_enabled(self):
        with patch("production.METADATA_RETRY_RELEASE_ENABLED", True), patch("urllib.request.build_opener") as opener:
            with self.assertRaisesRegex(SafetyError, "^live_execution_disabled$"):
                production._send_queue_delete(self.f.s, 7, blocklist=True)
        opener.assert_not_called()


if __name__ == "__main__":
    unittest.main()
