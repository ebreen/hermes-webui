"""PR 2 — end-to-end raw memory HTTP contract (hermex #58, §4/§8/§11/§12/§13/§14).

RED phase: this file must fail against the pinned SHA, where the raw route,
its dispatch, and the /api/system/health capability field do not exist yet.
Every test drives the real ``server.Handler`` over a real socket
(``ThreadingHTTPServer`` + ``http.client``, the repo's established
real-socket pattern) with an isolated profile/session/signing-key fixture, so
the failure mode is a missing route (404/405/501/200-preflight instead of the
contract status, or a missing ``capabilities`` member) — never a syntax or
collection error.

Coverage (contract §14 rows as they apply over HTTP):

1.  Nine fixture byte cases: GET /api/memory/raw?source=memory returns the
    exact canonical 200 body (fixture ``body_base64_chunks`` joined), exact
    ``Content-Length``, and the quoted ``repr-sha256`` representation ETag;
    source bytes are written to ``<profile-home>/memories/MEMORY.md``.
2.  ``If-None-Match`` exact/weak/wildcard matches → authenticated bodyless
    304 with no Content-Length/Content-Type/Content-Encoding/Vary/Trailer.
3.  ``read_only_auth_enabled() == auth_disabled`` → 403
    ``{"error":"forbidden"}`` with zero source reads (reader monkeypatched).
4.  HEAD/OPTIONS/POST/PUT/PATCH/DELETE → 405 + ``Allow: GET``; HEAD is
    bodyless with no Content-Length/Content-Type and ``Connection: close``.
5.  Missing/invalid session cookie → 401 ``{"error":"authentication_required"}``.
6.  All nine fixture provenance vectors over the wire (native 200,
    browser-same-origin 200, and the seven rejections).
7.  Unknown/duplicate query fields and forbidden selectors
    (path/workspace/profile) → 400 ``{"error":"invalid_request"}``.
8.  /api/system/health advertises ``capabilities.memory_raw_v1`` exactly
    matching the fixture's ``capability_supported``; auth-disabled →
    ``{"available": false}``.
9.  No-mutation integration: named mutating helpers monkeypatched to raise;
    the request-profile TLS slot untouched.
10. Concurrent readers (barrier-gated, no sleeps) all receive the identical
    canonical 200 response.
11. Request logs use the fixed ``/api/memory/raw`` label and contain no
    query/session/cookie material.

The HTTP harness is plain (non-TLS) HTTP, so the fixture's
``browser_same_origin`` vector is sent with ``http://`` origins — same-origin
semantics under the plain-HTTP canonical origin; the fixture's status
contract is what binds. Only the §11/§13 specific headers are asserted; the
Handler's unconditional CSP-Report-Only/Report-To headers are ignored.
"""
import base64
import hashlib
import hmac
import http.client
import json
import sys
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import api.auth as auth
import api.config as config
import api.memory_sources as ms
import api.profiles as profiles

_FIXTURE_PATH = Path(__file__).parent / "fixtures" / "memory_raw_v1.json"
_FIXTURE = json.loads(_FIXTURE_PATH.read_text(encoding="utf-8"))

_AUTH_ENV_VARS = (
    "HERMES_WEBUI_PASSWORD",
    "HERMES_WEBUI_PASSKEY",
    "HERMES_WEBUI_OIDC_ISSUER",
    "HERMES_WEBUI_OIDC_CLIENT_ID",
    "HERMES_WEBUI_OIDC_ALLOW_CLAIM",
    "HERMES_WEBUI_OIDC_ALLOW_VALUES",
    "HERMES_WEBUI_TRUSTED_AUTH_HEADER",
)

_TRUST_FORWARDED_ENV = (
    "HERMES_WEBUI_TRUST_FORWARDED_PROTO",
    "HERMES_WEBUI_TRUST_FORWARDED_HOST",
)

_ENDPOINT = "/api/memory/raw"
_SOURCE_QUERY = _ENDPOINT + "?source=memory"
_SESSION_COOKIE_NAME = "hermes_session"

# The nine provenance vectors from the fixture, with the browser-same-origin
# vector rewritten to http:// origins (plain-HTTP test harness; the fixture
# assumed an https deployment — same-origin semantics are preserved).
_PROVENANCE_VECTORS = []
for _case in _FIXTURE["provenance_cases"]:
    _headers = [(h, v) for h, v in _case["headers"]]
    if _case["id"] == "browser_same_origin":
        _headers = [
            (h, v.replace("https://", "http://") if h.lower() in ("origin", "referer") else v)
            for h, v in _headers
        ]
    _PROVENANCE_VECTORS.append(
        (
            _case["id"],
            _case["status"],
            _headers,
            bool(_case.get("trust_forwarded_proto", False)),
            bool(_case.get("trust_forwarded_host", False)),
        )
    )


def _boom(*_args, **_kwargs):
    raise AssertionError("mutating/forbidden helper must never be called")


def _write(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, bytes):
        path.write_bytes(data)
    else:
        path.write_text(data, encoding="utf-8")


def _signed_cookie(token: str, key: bytes) -> str:
    sig = hmac.new(key, token.encode(), hashlib.sha256).hexdigest()
    return f"{token}.{sig}"


def _canonical_dumps(envelope: dict) -> bytes:
    """The §11 required serializer, as an independent test reference."""
    return json.dumps(
        envelope,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _case(case_id: str) -> dict:
    return next(c for c in _FIXTURE["cases"] if c["id"] == case_id)


def _expected_body(case: dict) -> bytes:
    """Canonical 200 body: fixture body_base64_chunks joined, then decoded."""
    return base64.b64decode("".join(case["canonical_200"]["body_base64_chunks"]))


def _lf_expected_body() -> bytes:
    return _expected_body(_case("lf"))


def _write_lf_memory(env) -> None:
    _write(env.alice_home / "memories" / "MEMORY.md", base64.b64decode(_case("lf")["source_base64"]))


@pytest.fixture()
def raw_env(tmp_path, monkeypatch):
    """Isolated profile/session/signing-key state plus a real-socket server.

    The server runs ``server.Handler`` via ``ThreadingHTTPServer`` on an
    ephemeral port. ``server.check_auth`` is neutralized so requests reach the
    route layer: the raw branch must bypass generic auth anyway (§4), and at
    the RED SHA this keeps failures at the missing-route layer instead of the
    mutating auth machinery. Auth is ENABLED by default (password env var) so
    the route-local gate (PR 2) requires the minted session cookie.
    """
    state = tmp_path / "state"
    base = tmp_path / "base"
    monkeypatch.setattr(config, "STATE_DIR", state)
    monkeypatch.setattr(auth, "STATE_DIR", state)
    monkeypatch.setattr(ms, "STATE_DIR", state)
    monkeypatch.setattr(profiles, "_DEFAULT_HERMES_HOME", base)
    # Belt-and-braces: keep any RED-era mutating auth read away from real state.
    monkeypatch.setattr(auth, "_SESSIONS_FILE", state / ".sessions.json")

    import server as server_mod

    monkeypatch.setattr(server_mod, "check_auth", lambda handler, parsed: True)

    for name in _AUTH_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    for name in _TRUST_FORWARDED_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HERMES_WEBUI_PASSWORD", "pw")

    key = b"k" * 32
    _write(state / ".signing_key", key)
    token = "testtoken1234567890abcdef"
    session_cookie = _signed_cookie(token, key)
    _write(
        state / ".sessions.json",
        json.dumps(
            {
                token: {
                    "expiry": time.time() + 3600,
                    "profile": "alice",
                    "auth_type": "password",
                }
            }
        ),
    )
    alice_home = base / "profiles" / "alice"
    _write(
        alice_home / "config.yaml",
        "memory:\n  memory_enabled: true\n  user_profile_enabled: true\n",
    )

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server_mod.Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    env = SimpleNamespace(
        state=state,
        base=base,
        alice_home=alice_home,
        key=key,
        token=token,
        cookie=session_cookie,
        port=httpd.server_address[1],
        httpd=httpd,
        server_mod=server_mod,
    )
    try:
        yield env
    finally:
        httpd.shutdown()
        httpd.server_close()


def _auth_headers(env, **extra) -> dict:
    headers = {
        "Cookie": f"{_SESSION_COOKIE_NAME}={env.cookie}",
        "Host": "example.test",
        "Accept-Encoding": "identity",
    }
    headers.update(extra)
    return headers


def _request(port: int, method: str, path: str, headers=None, body=None, raw_headers=None):
    """One real-socket request; returns (status, [(name, value), ...], body)."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    try:
        if raw_headers is not None:
            # Raw header list (duplicate Host etc.) with no http.client defaults.
            conn.putrequest(method, path, skip_host=True)
            for name, value in raw_headers:
                conn.putheader(name, value)
            conn.endheaders(body)
        else:
            conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        data = resp.read()
        return resp.status, resp.getheaders(), data
    finally:
        conn.close()


def _header_map(headers) -> dict:
    return {k.lower(): v for k, v in headers}


class TestRawRoute200CanonicalBodies:
    """§13/§14 — all nine fixture byte cases round-trip exactly over HTTP."""

    @pytest.mark.parametrize("case", _FIXTURE["cases"], ids=[c["id"] for c in _FIXTURE["cases"]])
    def test_canonical_200_body_bytes(self, raw_env, case):
        source_bytes = base64.b64decode(case["source_base64"])
        _write(raw_env.alice_home / "memories" / "MEMORY.md", source_bytes)
        canonical = case["canonical_200"]
        expected_body = _expected_body(case)

        status, headers, body = _request(
            raw_env.port, "GET", _SOURCE_QUERY, headers=_auth_headers(raw_env)
        )

        assert status == 200
        assert body == expected_body, case["id"]
        h = _header_map(headers)
        assert h.get("content-length") == str(len(body)), case["id"]
        assert h.get("content-length") == canonical["headers"]["Content-Length"], case["id"]
        assert h.get("content-type") == canonical["headers"]["Content-Type"], case["id"]
        assert h.get("cache-control") == canonical["headers"]["Cache-Control"], case["id"]
        assert h.get("etag") == canonical["etag"], case["id"]
        assert h.get("date"), case["id"]
        # Compression disabled unconditionally; no Vary, no Content-Encoding.
        assert "content-encoding" not in h, case["id"]
        assert "vary" not in h, case["id"]
        # Representation digest over the exact canonical body bytes.
        rep = hashlib.sha256(body).hexdigest()
        assert rep == canonical["representation_sha256"], case["id"]
        assert rep != case["source_sha256"], case["id"]  # ETag scope: never a source hash

        envelope = json.loads(body)
        assert envelope["schema_version"] == 1
        assert envelope["source"] == _FIXTURE["canonical_case_mapping"]["source"]
        assert envelope["name"] == _FIXTURE["canonical_case_mapping"]["name"]
        assert envelope["content_type"] == _FIXTURE["canonical_case_mapping"]["content_type"]
        assert envelope["byte_length"] == case["source_byte_length"]
        assert envelope["data"] == case["source_base64"]
        assert envelope["checksum"] == {"algorithm": "sha-256", "value": case["source_sha256"]}
        assert envelope["source_version"] == case["source_version"]
        assert case["source_version"] == f"sha256:{case['source_sha256']}"
        # The wire body is exactly the §11 serializer output for that envelope.
        assert body == _canonical_dumps(envelope), case["id"]


class TestConditionalRequests:
    """§11/§13 — authenticated bodyless 304; no bypass without a match."""

    def _get_with_if_none_match(self, raw_env, value):
        return _request(
            raw_env.port,
            "GET",
            _SOURCE_QUERY,
            headers=_auth_headers(raw_env, **{"If-None-Match": value}),
        )

    def test_exact_strong_weak_and_wildcard_matches_return_bodyless_304(self, raw_env):
        _write_lf_memory(raw_env)
        fixture_etag = _case("lf")["canonical_200"]["etag"]
        for value in (
            fixture_etag,  # exact strong form (fixture conditional_304 request)
            f'W/{fixture_etag}',  # weak form compares equal
            "*",  # wildcard
        ):
            status, headers, body = self._get_with_if_none_match(raw_env, value)
            assert status == 304, value
            assert body == b"", value
            h = _header_map(headers)
            assert h.get("etag") == fixture_etag, value
            assert h.get("cache-control") == "private, no-store", value
            assert h.get("date"), value
            for absent in (
                "content-length",
                "content-type",
                "content-encoding",
                "vary",
                "trailer",
            ):
                assert absent not in h, (value, absent)

    def test_non_matching_if_none_match_returns_full_200(self, raw_env):
        _write_lf_memory(raw_env)
        status, headers, body = self._get_with_if_none_match(
            raw_env, '"repr-sha256:' + "0" * 64 + '"'
        )
        assert status == 200
        assert body == _lf_expected_body()
        h = _header_map(headers)
        assert h.get("etag") == _case("lf")["canonical_200"]["etag"]


class TestAuthGate:
    """§8 — the route-local authentication gate over HTTP."""

    def test_missing_and_invalid_session_cookie_return_401(self, raw_env, monkeypatch):
        # Prove the 401 comes from the raw route's gate, never generic
        # check_auth: the generic path is wired to raise.
        monkeypatch.setattr(raw_env.server_mod, "check_auth", _boom)
        monkeypatch.setattr(auth, "check_auth", _boom)
        variants = (
            None,  # no Cookie header at all
            "hermes_session=garbage",  # malformed value
            f"hermes_session={raw_env.token}.deadbeef",  # bad signature
        )
        for cookie in variants:
            headers = {"Host": "example.test", "Accept-Encoding": "identity"}
            if cookie is not None:
                headers["Cookie"] = cookie
            status, headers, body = _request(
                raw_env.port, "GET", _SOURCE_QUERY, headers=headers
            )
            assert status == 401, cookie
            assert body == b'{"error":"authentication_required"}', cookie
            assert "set-cookie" not in _header_map(headers), cookie

    def test_auth_disabled_returns_403_forbidden_with_zero_source_reads(
        self, raw_env, monkeypatch
    ):
        for name in _AUTH_ENV_VARS:
            monkeypatch.delenv(name, raising=False)
        calls = []

        def _never_read(*_args, **_kwargs):
            calls.append(1)
            raise AssertionError("source read must not happen when auth is disabled")

        monkeypatch.setattr(ms, "read_memory_source", _never_read)
        import api.routes as routes

        if hasattr(routes, "read_memory_source"):
            monkeypatch.setattr(routes, "read_memory_source", _never_read)

        status, headers, body = _request(
            raw_env.port, "GET", _SOURCE_QUERY, headers=_auth_headers(raw_env)
        )
        assert status == 403
        assert body == b'{"error":"forbidden"}'
        assert calls == []


class TestMethodDispatch:
    """§4 — exact-path method contract: only GET is allowed."""

    @pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
    def test_unsafe_methods_are_405_with_allow_get(self, raw_env, method):
        # Positive Content-Length framing: the body is never consumed, the
        # connection is closed without reading it.
        status, headers, body = _request(
            raw_env.port, method, _ENDPOINT, headers={"Host": "example.test"}, body=b"data"
        )
        assert status == 405, method
        h = _header_map(headers)
        assert h.get("allow") == "GET", method
        assert h.get("connection") == "close", method
        assert body == b'{"error":"method_not_allowed"}', method
        assert h.get("content-length") == str(len(body)), method
        assert "set-cookie" not in h, method

    def test_options_is_405_with_allow_get(self, raw_env):
        status, headers, body = _request(raw_env.port, "OPTIONS", _ENDPOINT)
        assert status == 405
        h = _header_map(headers)
        assert h.get("allow") == "GET"
        assert body == b'{"error":"method_not_allowed"}'
        assert h.get("content-length") == str(len(body))
        assert "set-cookie" not in h

    def test_head_is_405_bodyless_without_framing_headers(self, raw_env):
        status, headers, body = _request(raw_env.port, "HEAD", _ENDPOINT)
        assert status == 405
        h = _header_map(headers)
        assert h.get("allow") == "GET"
        assert h.get("connection") == "close"
        assert body == b""
        assert "content-length" not in h
        assert "content-type" not in h


class TestProvenance:
    """§8/§13 — all nine fixture provenance vectors over the wire."""

    @pytest.mark.parametrize(
        "vector",
        _PROVENANCE_VECTORS,
        ids=[v[0] for v in _PROVENANCE_VECTORS],
    )
    def test_provenance_vector_status(self, raw_env, monkeypatch, vector):
        case_id, expected_status, headers, trust_proto, trust_host = vector
        _write_lf_memory(raw_env)
        if trust_proto:
            monkeypatch.setenv("HERMES_WEBUI_TRUST_FORWARDED_PROTO", "1")
        else:
            monkeypatch.delenv("HERMES_WEBUI_TRUST_FORWARDED_PROTO", raising=False)
        if trust_host:
            monkeypatch.setenv("HERMES_WEBUI_TRUST_FORWARDED_HOST", "1")
        else:
            monkeypatch.delenv("HERMES_WEBUI_TRUST_FORWARDED_HOST", raising=False)

        wire_headers = list(headers) + [
            ("Cookie", f"{_SESSION_COOKIE_NAME}={raw_env.cookie}")
        ]
        status, headers, body = _request(
            raw_env.port, "GET", _SOURCE_QUERY, raw_headers=wire_headers
        )

        assert status == expected_status, case_id
        if expected_status == 200:
            h = _header_map(headers)
            assert h.get("content-length") == str(len(_lf_expected_body())), case_id
            assert body == _lf_expected_body(), case_id
        else:
            assert body == b'{"error":"forbidden"}', case_id


class TestQueryValidation:
    """§4 — strict query grammar: unknown/duplicate fields and selectors."""

    @pytest.mark.parametrize(
        "query",
        [
            "?source=memory&extra=1",  # unknown field
            "?source=memory&source=memory",  # duplicate decoded name
            "?source=memory&path=/etc/passwd",  # forbidden path selector
            "?source=memory&workspace=/tmp",  # forbidden workspace selector
            "?source=memory&profile=alice",  # forbidden profile selector
            "?source=",  # empty value
            "",  # missing source
        ],
        ids=[
            "unknown_field",
            "duplicate_source",
            "path_selector",
            "workspace_selector",
            "profile_selector",
            "empty_source_value",
            "missing_source",
        ],
    )
    def test_invalid_query_returns_400(self, raw_env, query):
        status, headers, body = _request(
            raw_env.port, "GET", _ENDPOINT + query, headers=_auth_headers(raw_env)
        )
        assert status == 400, query
        assert body == b'{"error":"invalid_request"}', query


class TestHealthCapability:
    """§12 — /api/system/health advertises memory_raw_v1 exactly."""

    def test_health_advertises_supported_capability(self, raw_env):
        status, headers, body = _request(
            raw_env.port, "GET", "/api/system/health", headers=_auth_headers(raw_env)
        )
        assert status == 200
        payload = json.loads(body)
        assert payload["capabilities"]["memory_raw_v1"] == _FIXTURE["capability_supported"]

    def test_health_capability_false_when_auth_disabled(self, raw_env, monkeypatch):
        for name in _AUTH_ENV_VARS:
            monkeypatch.delenv(name, raising=False)
        status, headers, body = _request(
            raw_env.port, "GET", "/api/system/health", headers=_auth_headers(raw_env)
        )
        assert status == 200
        payload = json.loads(body)
        assert payload["capabilities"]["memory_raw_v1"] == _FIXTURE["capability_unsupported"]


class TestNoMutation:
    """§5 — the raw path is a no-mutation boundary; TLS slot untouched."""

    _MUTATING_AUTH_HELPERS = (
        "get_profile_cookie",
        "get_profile_cookie_name",
        "parse_cookie",
        "verify_profile_cookie_value",
        "verify_session",
        "get_session_info",
        "check_auth",
        "ensure_trusted_auth_session",
        "is_auth_enabled",
        "is_password_auth_enabled",
        "get_password_hash",
        "_load_key",
        "_pbkdf2_key",
        "_signing_key",
        "_prune_expired_sessions",
        "_save_sessions",
        "_queue_pending_cookie",
    )
    _MUTATING_PROFILE_HELPERS = (
        "set_request_profile",
        "clear_request_profile",
        "get_active_profile_name",
        "_profiles_match",
    )
    _MUTATING_CONFIG_HELPERS = (
        "get_config",
        "get_config_snapshot",
        "_refresh_config_cache",
    )

    def test_raw_get_never_reaches_mutating_helpers_and_leaves_tls_untouched(
        self, raw_env, monkeypatch
    ):
        _write_lf_memory(raw_env)
        for name in self._MUTATING_AUTH_HELPERS:
            if hasattr(auth, name):
                monkeypatch.setattr(auth, name, _boom)
        for name in self._MUTATING_PROFILE_HELPERS:
            if hasattr(profiles, name):
                monkeypatch.setattr(profiles, name, _boom)
        for name in self._MUTATING_CONFIG_HELPERS:
            if hasattr(config, name):
                monkeypatch.setattr(config, name, _boom)
        # server.py's own import bindings of the request-profile mutators.
        monkeypatch.setattr(raw_env.server_mod, "set_request_profile", _boom)
        monkeypatch.setattr(raw_env.server_mod, "clear_request_profile", _boom)

        tls = profiles._tls
        slot_before = getattr(tls, "profile", None)

        status, headers, body = _request(
            raw_env.port, "GET", _SOURCE_QUERY, headers=_auth_headers(raw_env)
        )

        assert status == 200
        assert body == _lf_expected_body()
        assert getattr(tls, "profile", None) is slot_before


class TestConcurrentReaders:
    """§10/§14 — barrier-gated concurrent readers get identical canonical 200s."""

    def test_concurrent_readers_all_get_identical_200(self, raw_env):
        _write_lf_memory(raw_env)
        n = 4
        barrier = threading.Barrier(n)
        results = []

        def _worker():
            barrier.wait()
            status, headers, body = _request(
                raw_env.port, "GET", _SOURCE_QUERY, headers=_auth_headers(raw_env)
            )
            results.append((status, body))

        threads = [threading.Thread(target=_worker) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=20)

        assert len(results) == n
        expected = _lf_expected_body()
        for status, body in results:
            assert status == 200
            assert body == expected


class TestLogging:
    """§5/§11 — fixed /api/memory/raw label; no query/session/cookie material."""

    def test_request_log_uses_fixed_label_and_never_logs_sensitive_material(
        self, raw_env, capsys
    ):
        _write_lf_memory(raw_env)
        cookie_value = f"{_SESSION_COOKIE_NAME}={raw_env.cookie}"
        status, headers, body = _request(
            raw_env.port,
            "GET",
            f"{_ENDPOINT}?source=memory&session_id=SECRETQUERY",
            headers={
                "Cookie": cookie_value,
                "Host": "example.test",
                "Accept-Encoding": "identity",
            },
        )

        captured = capsys.readouterr().out
        # The fixed route label is present in the request log.
        assert _ENDPOINT in captured
        # And no query, session-id, selector, or cookie material leaks into it.
        assert "session_id" not in captured
        assert "SECRETQUERY" not in captured
        assert "source=memory" not in captured
        assert raw_env.token not in captured
        assert raw_env.cookie not in captured
        assert cookie_value not in captured
