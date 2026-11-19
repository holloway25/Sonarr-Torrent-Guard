"""Non-saving Sonarr-side connectivity diagnostic; never test saved categories."""

import copy
import json
import time
import urllib.error
import urllib.request

from guard import hard_deadline, unique_response_keys
from safety import SafetyError

RETRY_AFTER_SECONDS = 600


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise SafetyError("connectivity_redirect_refused")


def probe_payload(client):
    # Keep the original ID so Sonarr resolves its masked stored credentials.
    # Empty categories avoid TestCategory's AddLabel calls. This test does not
    # save configuration; Sonarr may update its native provider health status.
    # Never substitute the guard's credentials for Sonarr's saved credentials.
    value = copy.deepcopy(client)
    fields = value.get("fields")
    if not isinstance(fields, list) or any(not isinstance(f, dict) for f in fields):
        raise SafetyError("invalid_client_response")
    for name in ("tvCategory", "tvImportedCategory"):
        fields = [f for f in fields if f.get("name") != name]
        fields.append({"name": name, "value": ""})
    value["fields"] = fields
    return value


def sonarr_probe(api, payload):
    request = urllib.request.Request(api.config["url"].rstrip("/") + "/api/v3/downloadclient/test",
        data=json.dumps(payload).encode(), method="POST",
        headers={"X-Api-Key": api.config["api_key"], "Content-Type": "application/json"})
    deadline = min(api.deadline or float("inf"), time.monotonic() + 15)
    try:
        with hard_deadline(deadline):
            try:
                response = urllib.request.build_opener(NoRedirect()).open(request, timeout=15)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                status, raw = response.code, response.read(8193)
            if len(raw) > 8192:
                raise ValueError()
            return status, json.loads(raw, object_pairs_hook=unique_response_keys)
    except Exception:
        raise SafetyError("sonarr_connectivity_unavailable") from None


def require_connectivity(config, api, label, probe=None):
    from production import bound_client, require_sonarr_v4
    try:
        require_sonarr_v4(api)
        client = bound_client(config, api, label)
        status, result = (probe or sonarr_probe)(api, probe_payload(client))
        # Empty-category warning is expected. Any other warning/error, malformed
        # result or hidden/masked credentials failing authentication means wait.
        ok = status == 200 and result == {}
        warning = (status == 400 and isinstance(result, list) and len(result) == 1
                   and isinstance(result[0], dict) and result[0].get("isWarning") is True
                   # Reviewed Sonarr uses isWarning, even when FluentValidation
                   # serializes its separate severity field as "error".
                   and result[0].get("propertyName") == "TvCategory")
        if not (ok or warning):
            raise SafetyError("sonarr_connectivity_unavailable")
        return {"status": "verified", "checked_at": time.time(), "retry_after_seconds": RETRY_AFTER_SECONDS}
    except SafetyError:
        raise
    except Exception:
        raise SafetyError("sonarr_connectivity_unavailable") from None
