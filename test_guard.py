import copy
import unittest
from unittest.mock import patch

from guard import (Api, GuardError, SameOriginRedirect, PrivateRotatingFileHandler,
                   assess_files, load_config, load_batch_state, save_batch_state, records, run)


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
        self.config["qbittorrent"] = {"url": "https://downloader.example.invalid"}
        self.config["sonarr"]["HD"]["download_client_binding"] = {
            "id": 1, "endpoint": "https://downloader.example.invalid:443"}
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
                              "implementation": "QBittorrent", "fields": [
                                  {"name": "tvCategory", "value": "tv-hd"},
                                  {"name": "host", "value": "downloader.example.invalid"},
                                  {"name": "port", "value": 443},
                                  {"name": "useSsl", "value": True},
                                  {"name": "urlBase", "value": None}]}]})

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

    def test_same_hash_on_another_downloader_is_protected(self):
        fields = self.s.routes["/api/v3/downloadclient"][0]["fields"]
        for field in fields:
            if field["name"] == "host":
                field["value"] = "other-downloader.example.invalid"
        self.assertEqual(self.check()["reason"], "sonarr_downloader_binding_mismatch")
        self.assertFalse(any(route.endswith("/files") for route, _ in self.qb.calls))

    def test_binding_pins_client_id_monitor_and_actual_endpoint(self):
        item = self.config["sonarr"]["HD"]
        for binding in (None, {"id": 2, "endpoint": self.config["qbittorrent"]["url"]},
                        {"id": 1, "endpoint": "https://other.example.invalid"}):
            with self.subTest(binding=binding):
                item["download_client_binding"] = binding
                self.assertEqual(self.check()["decision"], "skip")

    def test_binding_endpoint_port_scheme_and_base_path_changes_are_protected(self):
        client = self.s.routes["/api/v3/downloadclient"][0]
        original = copy.deepcopy(client["fields"])
        for key, value in (("port", 8443), ("useSsl", False), ("urlBase", "/different")):
            client["fields"] = copy.deepcopy(original)
            for field in client["fields"]:
                if field["name"] == key:
                    field["value"] = value
            with self.subTest(key=key):
                self.assertEqual(self.check()["reason"], "sonarr_downloader_binding_mismatch")

    def test_pinned_client_selected_among_same_category_downloaders(self):
        clients = self.s.routes["/api/v3/downloadclient"]
        pinned = copy.deepcopy(clients[0])
        other = copy.deepcopy(pinned)
        other.update(id=2, name="Other Downloader")
        for field in other["fields"]:
            if field["name"] == "host":
                field["value"] = "other-downloader.example.invalid"
        for ordering in ([other, pinned], [pinned, other]):
            with self.subTest(order=[c["id"] for c in ordering]):
                self.s.routes["/api/v3/downloadclient"] = ordering
                self.assertEqual(self.check()["decision"], "would_fail")
                self.assertTrue(any(route.endswith("/files") for route, _ in self.qb.calls))

    def test_duplicate_pinned_client_ids_are_still_ambiguous(self):
        clients = self.s.routes["/api/v3/downloadclient"]
        clients.append(copy.deepcopy(clients[0]))
        self.assertEqual(self.check()["reason"], "ambiguous_download_client")
        self.assertFalse(any(route.endswith("/files") for route, _ in self.qb.calls))

    def test_missing_or_disabled_pinned_client_does_not_fall_back(self):
        original = copy.deepcopy(self.s.routes["/api/v3/downloadclient"][0])
        other = dict(original, id=2, name="Other Downloader")
        for clients in ([other], [dict(original, enable=False), other]):
            with self.subTest(clients=[c["id"] for c in clients]):
                self.s.routes["/api/v3/downloadclient"] = clients
                self.assertEqual(self.check()["reason"], "ambiguous_download_client")
                self.assertFalse(any(route.endswith("/files") for route, _ in self.qb.calls))

    def test_queue_bound_to_other_client_id_is_still_protected(self):
        clients = self.s.routes["/api/v3/downloadclient"]
        clients.append(dict(clients[0], id=2, name="Other Downloader"))
        self.s.routes["/api/v3/queue"]["records"][0]["downloadClientId"] = 2
        self.assertEqual(self.check()["reason"], "wrong_download_client")
        self.assertFalse(any(route.endswith("/files") for route, _ in self.qb.calls))

    def test_unrelated_hash_does_not_consume_budget(self):
        unrelated = dict(self.row, id=99, downloadId="b" * 40)
        self.s.routes["/api/v3/queue"] = {"totalRecords": 2, "records": [unrelated, self.row]}
        self.config["max_torrents_per_run"] = 1
        state = {}
        for _ in range(2):
            result = run(self.config, self.qb, {"HD": self.s}, now=1000, batch_state=state)
            self.assertEqual([r["hash"] for r in result if r["decision"] == "would_fail"], [self.h])

    def test_later_candidates_receive_turns_across_restarts(self):
        import tempfile
        from pathlib import Path
        other = "b" * 40
        self.config["max_torrents_per_run"] = 1
        self.s.routes["/api/v3/queue"] = {"totalRecords": 2, "records": [
            self.row, dict(self.row, id=2, downloadId=other)]}
        self.s.routes["/api/v3/history"] = {"totalRecords": 2, "records": [
            self.grab, dict(self.grab, id=5, downloadId=other)]}
        self.qb.routes["/api/v2/torrents/info"].append(dict(self.t, hash=other))
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/"batch-state.json"
            assessed = []
            for _ in range(4):
                state = load_batch_state(path)
                result = run(self.config, self.qb, {"HD": self.s}, now=1000, batch_state=state)
                assessed.extend(r["hash"] for r in result if r["decision"] == "would_fail")
                save_batch_state(path, state)
                # Even if the API changes ordering, stable keys preserve fairness.
                self.s.routes["/api/v3/queue"]["records"].reverse()
            self.assertEqual(assessed, [self.h, other, self.h, other])

    def test_rotation_across_instances(self):
        other = "b" * 40
        uhd = copy.deepcopy(self.s)
        uhd.routes["/api/v3/queue"]["records"][0]["downloadId"] = other
        uhd.routes["/api/v3/history"]["records"][0]["downloadId"] = other
        self.qb.routes["/api/v2/torrents/info"].append(dict(self.t, hash=other, category="tv-uhd"))
        self.config["sonarr"]["UHD"] = copy.deepcopy(self.config["sonarr"]["HD"])
        self.config["sonarr"]["UHD"]["category"] = "tv-uhd"
        uhd.routes["/api/v3/downloadclient"][0]["fields"][0]["value"] = "tv-uhd"
        self.config["max_torrents_per_run"] = 1
        state, assessed = {}, []
        for _ in range(2):
            result = run(self.config, self.qb, {"HD": self.s, "UHD": uhd}, now=1000, batch_state=state)
            assessed.extend(r["instance"] for r in result if r["decision"] == "would_fail")
        self.assertEqual(assessed, ["HD", "UHD"])

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
    @unittest.skipUnless(__import__("os").name == "posix", "Linux hard deadline")
    def test_deadline_interrupts_slow_stream_before_complete_body(self):
        import http.server, threading, time
        class Slow(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = b'{"data":"' + b'x' * 40 + b'"}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    for byte in body:
                        self.wfile.write(bytes([byte]))
                        self.wfile.flush()
                        time.sleep(0.02)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            def log_message(self, *args):
                pass
        server = http.server.ThreadingHTTPServer(("localhost", 0), Slow)
        thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
        thread.start()
        start = time.monotonic()
        try:
            api = Api({"url": "http://localhost:" + str(server.server_port)},
                      timeout=2, deadline=start + 0.12)
            with self.assertRaisesRegex(GuardError, "run_time_limit_reached"):
                api.call("/slow")
            self.assertLess(time.monotonic() - start, 0.5)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)

    @unittest.skipUnless(__import__("os").name == "posix", "Linux permissions")
    def test_rotated_logs_and_existing_backups_remain_private(self):
        import logging, os, stat, tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/"guard.log"
            path.write_text("old log\n")
            backup = Path(str(path) + ".1")
            backup.write_text("old backup\n")
            for p in (path, backup):
                p.chmod(0o644)
            previous = os.umask(0o022)
            handler = None
            try:
                handler = PrivateRotatingFileHandler(path, maxBytes=30, backupCount=3)
                for _ in range(5):
                    handler.emit(logging.LogRecord("test", logging.INFO, "", 1, "report" * 10, (), None))
                handler.flush()
                for p in Path(folder).iterdir():
                    self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
            finally:
                if handler:
                    handler.close()
                os.umask(previous)

    def test_equivalent_default_port_redirects_are_accepted(self):
        import urllib.request
        for before, after in (("https://example.invalid/api?x=1", "https://example.invalid:443/api?x=2"),
                              ("http://example.invalid:80/api", "http://example.invalid/api")):
            req = urllib.request.Request(before)
            redirected = SameOriginRedirect().redirect_request(req, None, 302, "", {}, after)
            self.assertEqual(redirected.full_url, after)

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
        for target in ("http://example.invalid/api", "https://other.invalid/api",
                       "https://example.invalid:8443/api"):
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
