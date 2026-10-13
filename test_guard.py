import copy
import unittest
from unittest.mock import patch

from guard import Api, GuardError, SameOriginRedirect, assess_files, load_config, records, run


def manifest(*entries):
    return [{"index": n, "name": name, "priority": priority, "size": 100,
             "progress": 0} for n, (name, priority) in enumerate(entries)]


class FilesTests(unittest.TestCase):
    def test_policy(self):
        cases = [
            (manifest(("video.mkv", 1), ("subtitles.zip", 0), ("link.lnk", 0)), []),
            (manifest(("video.mkv", 1), ("nested/PAYLOAD.EXE", 0)), ["contains_exe"]),
            (manifest(("video.mkv", 1), ("nested\\payload.SCR", 0)), ["contains_scr"]),
            (manifest(("payload.exe", 0)), ["contains_exe", "all_files_unselected"]),
            (manifest(("nested/info.TXT", 1), ("release.NFO", 1)), ["only_txt_nfo_selected"]),
            (manifest(("subtitle.srt", 1), ("info.nfo", 1)), []),
            (manifest(("subtitle.zip", 0)), ["all_files_unselected"]),
            (manifest(("link.lnk", 0), ("info.txt", 1)), ["only_txt_nfo_selected"]),
        ]
        for files, wanted in cases:
            with self.subTest(files=files):
                self.assertEqual(assess_files(files), wanted)

    def test_padding_size_does_not_protect_text(self):
        files = manifest(("info.nfo", 1))
        files[0]["size"] = 10**12
        self.assertEqual(assess_files(files), ["only_txt_nfo_selected"])

    def test_invalid_or_partial_manifest_is_not_failure(self):
        invalid = [[], None, {}, [{"name": "payload.exe"}]]
        for field, value in (("priority", None), ("priority", True), ("index", 2),
                             ("size", -1), ("progress", float("nan")), ("name", "")):
            f = manifest(("payload.exe", 0))
            f[0][field] = value
            invalid.append(f)
        invalid.append(manifest(("a.exe", 0)) * 2)
        for files in invalid:
            with self.subTest(files=files), self.assertRaises(GuardError):
                assess_files(files)


class FakeApi:
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def call(self, route, params=None):
        self.calls.append((route, params))
        result = self.routes[route]
        if isinstance(result, Exception):
            raise result
        return copy.deepcopy(result)


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.h = "a" * 40
        self.config = {"sonarr": {"HD": {"category": "tv-hd", "indexers": {
            "public": ["Public Source"], "private": ["Private Source"]}}}}
        self.row = {"id": 1, "downloadId": self.h.upper(), "seriesId": 2,
                    "episodeId": 3, "downloadClient": "Downloader"}
        self.grab = {"id": 4, "downloadId": self.h, "seriesId": 2, "episodeId": 3,
                     "eventType": "grabbed", "data": {"indexer": "Public Source"}}
        self.t = {"hash": self.h, "category": "tv-hd", "state": "stoppedUP", "added_on": 100}
        self.qb = FakeApi({"/api/v2/torrents/info": [self.t],
                           "/api/v2/torrents/files": manifest(("episode.exe", 0))})
        self.s = FakeApi({"/api/v3/queue": {"totalRecords": 1, "records": [self.row]},
                          "/api/v3/history": {"totalRecords": 1, "records": [self.grab]},
                          "/api/v3/downloadclient": [{"id": 1, "name": "Downloader", "enable": True,
                              "implementation": "QBittorrent", "fields": [{"name": "tvCategory", "value": "tv-hd"}]}]})

    def check(self):
        return run(self.config, self.qb, {"HD": self.s}, now=1000)[0]

    def test_stopped_bad_torrent_is_candidate_without_mutations(self):
        report = self.check()
        self.assertEqual(report["decision"], "would_fail")
        self.assertTrue(report["dry_run"])
        allowed = {"/api/v2/torrents/info", "/api/v2/torrents/files", "/api/v3/queue",
                   "/api/v3/history", "/api/v3/downloadclient"}
        self.assertTrue(all(route in allowed for route, _ in self.qb.calls + self.s.calls))

    def test_stopped_good_torrent_is_kept(self):
        self.qb.routes["/api/v2/torrents/files"] = manifest(("episode.mkv", 1))
        self.assertEqual(self.check()["decision"], "keep")

    def test_source_protections(self):
        for source in ("Private Source", "New Unclassified Source"):
            with self.subTest(source=source):
                self.s.routes["/api/v3/history"]["records"][0]["data"]["indexer"] = source
                self.assertEqual(self.check()["decision"], "skip")
                self.assertFalse(any(route.endswith("/files") for route, _ in self.qb.calls))

    def test_wrong_category(self):
        self.qb.routes["/api/v2/torrents/info"][0]["category"] = "other"
        self.assertEqual(self.check()["reason"], "missing_torrent_or_wrong_category")

    def test_manual_torrent_has_no_ownership(self):
        self.s.routes["/api/v3/history"] = {"totalRecords": 0, "records": []}
        self.assertEqual(self.check()["reason"], "no_sonarr_grab_history")

    def test_history_filter_preserves_sonarr_hash_case(self):
        self.check()
        queries = [params for route, params in self.s.calls if route == "/api/v3/history"]
        self.assertEqual(queries[0]["downloadId"], self.h.upper())

    def test_other_client_not_assessed(self):
        self.s.routes["/api/v3/queue"]["records"][0]["downloadClient"] = "Other Client"
        self.assertEqual(self.check()["reason"], "unconfirmed_download_client")

    def test_identity_mismatch(self):
        self.s.routes["/api/v3/history"]["records"][0]["episodeId"] = 99
        self.assertEqual(self.check()["reason"], "content_identity_not_in_grab_history")

    def test_metadata_age_and_transitional_states(self):
        for state in ("metaDL", "checkingUP", "moving", "error", "unknown"):
            with self.subTest(state=state):
                self.qb.routes["/api/v2/torrents/info"][0]["state"] = state
                self.assertEqual(self.check()["decision"], "skip")
        self.qb.routes["/api/v2/torrents/info"][0].update(state="downloading", added_on=999)
        self.assertEqual(self.check()["reason"], "torrent_too_new_or_age_unknown")

    def test_api_failure_not_interpreted_as_bad_torrent(self):
        self.qb.routes["/api/v2/torrents/files"] = GuardError("api_request_or_response_failed")
        self.assertEqual(self.check()["decision"], "skip")

    def test_duplicate_ownership_is_protected(self):
        self.config["sonarr"]["UHD"] = copy.deepcopy(self.config["sonarr"]["HD"])
        result = run(self.config, self.qb, {"HD": self.s, "UHD": self.s}, now=1000)
        self.assertTrue(all(r["reason"] == "ambiguous_instance_ownership" for r in result))

    def test_valid_file_selected_before_next_run_cancels_text_failure(self):
        self.qb.routes["/api/v2/torrents/files"] = manifest(("info.txt", 1), ("episode.mkv", 0))
        self.assertEqual(self.check()["decision"], "would_fail")
        self.qb.routes["/api/v2/torrents/files"][1]["priority"] = 1
        self.assertEqual(self.check()["decision"], "keep")

    def test_episode_rows_grouped_to_one_proposal(self):
        row = dict(self.row, id=2, episodeId=5)
        grab = dict(self.grab, id=5, episodeId=5)
        self.s.routes["/api/v3/queue"] = {"totalRecords": 2, "records": [self.row, row]}
        self.s.routes["/api/v3/history"] = {"totalRecords": 2, "records": [self.grab, grab]}
        self.assertEqual(len(run(self.config, self.qb, {"HD": self.s}, now=1000)), 1)


class TransportTests(unittest.TestCase):
    @unittest.skipUnless(__import__("os").name == "posix", "Linux process locking")
    def test_overlapping_cli_run_exits_before_api_access(self):
        import fcntl, json, os, subprocess, sys, tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder)/"settings.json"
            sample = json.loads((Path(__file__).parent/"config.example.json").read_text())
            p.write_text(json.dumps(sample))
            os.chmod(p, 0o600)
            with open(Path(folder)/"guard.lock", "a") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                r = subprocess.run([sys.executable, str(Path(__file__).parent/"guard.py"),
                                    "--config", str(p)], capture_output=True, text=True, timeout=5)
                self.assertEqual(r.returncode, 1)
                self.assertIn("another_run_is_active", r.stderr)

    def test_login_204_empty_body_accepted_if_authenticated_endpoint_works(self):
        api = Api({"url": "https://example.invalid", "username": "example", "password": "placeholder"})
        with patch.object(api, "call", side_effect=[None, "2.11.4"]) as call:
            self.assertEqual(api.login(), "2.11.4")
            self.assertEqual(call.call_args_list[0].kwargs, {"login": True})

    def test_cross_origin_and_https_downgrade_refused(self):
        import urllib.request
        req = urllib.request.Request("https://example.invalid/api")
        for target in ("http://example.invalid/api", "https://other.invalid/api"):
            with self.assertRaises(GuardError):
                SameOriginRedirect().redirect_request(req, None, 302, "", {}, target)

    def test_truncated_duplicate_or_changing_pages_refused(self):
        for payload in ({"totalRecords": 1, "records": []},
                        {"totalRecords": 2, "records": [{"id": 1}, {"id": 1}]},
                        {"records": []}):
            with self.assertRaises(GuardError):
                records(FakeApi({"queue": payload}), "queue", max_pages=1)
        api = FakeApi({})
        with patch.object(api, "call", side_effect=[{"totalRecords": 2, "records": [{"id": 1}]},
                                                   {"totalRecords": 1, "records": [{"id": 2}]}]):
            with self.assertRaises(GuardError):
                records(api, "queue")

    def test_live_config_refused(self):
        from pathlib import Path
        import tempfile, json, os
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder)/"settings.json"
            p.write_text(json.dumps({"dry_run": False}))
            os.chmod(p, 0o600)
            with self.assertRaisesRegex(GuardError, "only_dry_run_supported"):
                load_config(p)


if __name__ == "__main__":
    unittest.main()
