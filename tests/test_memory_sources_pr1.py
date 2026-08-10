"""PR 1 — api/memory_sources.py anchored raw reader + fixture/docs tests (hermex #58, §9/§10/§11/§13/§14).

Tests the PR 1 module DIRECTLY (no HTTP, no dispatch, no capability):

- Fixed source resolution through ``AuthorizedRawProfileContext`` (§9): the four
  fixed selectors, profile-local default/trusted workspace resolvers, the
  read-only session-metadata seam, feature gates, and the workspace-first
  Git-root candidate order.
- The race-resistant bounded reader (§10): anchored dir_fd traversal with
  held anchor-parent/anchor FDs, component-wise no-follow namespace checks,
  pre/post identity tuples, the bounded short-read loop, and the fixed
  200/404/409/413/503 outcome mapping.
- Envelope construction and the canonical serializer (§11): sort_keys/compact/
  ensure_ascii/allow_nan=False UTF-8 JSON, source-byte checksum/source_version,
  representation SHA-256 and the quoted ``repr-sha256`` ETag, compression
  disabled, exact Content-Length.
- The checked-in fixture ``tests/fixtures/memory_raw_v1.json`` (§13): every one
  of the nine byte cases, the bodyless 304, and all nine provenance vectors.
- Strict query parsing (§4) and provenance validation (§8) as pure module
  helpers, plus limit configuration and the bounded semaphore.
- The no-mutation suite (§5): every named mutating helper monkeypatched to
  raise; no files created; the request-profile TLS slot untouched.

Still no public dispatch and no capability: the route is not reachable over
HTTP and /api/system/health does not advertise memory_raw_v1 (PR 2).
"""
import base64
import dataclasses
import hashlib
import json
import os
import stat
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import api.auth as auth
import api.config as config
import api.models as models
import api.workspace as workspace

import api.memory_sources as ms

WINDOWS = sys.platform == "win32"
requires_symlink = pytest.mark.skipif(
    WINDOWS,
    reason="symlink creation needs privileges on Windows",
)

_FIXTURE_PATH = Path(__file__).parent / "fixtures" / "memory_raw_v1.json"
_FIXTURE = json.loads(_FIXTURE_PATH.read_text(encoding="utf-8"))

_MUTATING_AUTH_HELPERS = (
    "_load_key",
    "_pbkdf2_key",
    "_signing_key",
    "_hash_password",
    "get_password_hash",
    "is_auth_enabled",
    "is_password_auth_enabled",
    "are_passkeys_enabled",
    "is_oidc_auth_enabled",
    "is_trusted_auth_enabled",
    "verify_session",
    "get_session_info",
    "session_bound_profile",
    "create_session",
    "invalidate_session",
    "verify_password",
    "_prune_expired_sessions",
    "_save_sessions",
    "_load_sessions",
    "_queue_pending_cookie",
    "parse_cookie",
    "check_auth",
    "ensure_trusted_auth_session",
    "sign_profile_cookie_value",
    "verify_profile_cookie_value",
    "get_profile_cookie",
    "get_profile_cookie_name",
)

_MUTATING_PROFILE_HELPERS = (
    "set_request_profile",
    "clear_request_profile",
    "get_active_profile_name",
    "_profiles_match",
    "_is_root_profile",
    "list_profiles_api",
    "_invalidate_root_profile_cache",
    "_create_profile_fallback",
)

_MUTATING_CONFIG_HELPERS = (
    "get_config",
    "get_config_snapshot",
    "load_settings",
    "save_settings",
    "reload_config",
    "reload_config_if_stale",
    "_refresh_config_cache",
    "get_config_for_profile_home",
)

_MUTATING_WORKSPACE_HELPERS = (
    "load_workspaces",
    "_clean_workspace_list",
    "_migrate_global_workspaces",
    "_profile_state_dir",
    "get_last_workspace",
    "_profile_default_workspace",
    "save_last_workspace",
    "resolve_trusted_workspace",
    "_workspaces_file",
    "_last_workspace_file",
)


def _boom(*_args, **_kwargs):
    raise AssertionError("mutating/forbidden helper must never be called")


def _write(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, bytes):
        path.write_bytes(data)
    else:
        path.write_text(data, encoding="utf-8")


def _tree_snapshot(root: Path) -> dict:
    if not root.exists():
        return {}
    out = {}
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        try:
            if path.is_file() and not path.is_symlink():
                out[str(rel)] = path.read_bytes()
            else:
                out[str(rel)] = None
        except OSError:
            out[str(rel)] = None
    return out


def _canonical_dumps(envelope: dict) -> bytes:
    """The §11 required serializer, as an independent test reference."""
    return json.dumps(
        envelope,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


@pytest.fixture()
def iso_state(tmp_path, monkeypatch):
    """Isolated STATE_DIR and Hermes base home; ctx is built by the test."""
    state = tmp_path / "state"
    base = tmp_path / "base"
    monkeypatch.setattr(auth, "STATE_DIR", state)
    monkeypatch.setattr(config, "STATE_DIR", state)
    monkeypatch.setattr(ms, "STATE_DIR", state)
    return SimpleNamespace(state=state, base=base, root=tmp_path)


def _ctx(iso, profile="alice") -> auth.AuthorizedRawProfileContext:
    home = iso.base / "profiles" / profile if profile != "default" else iso.base
    return auth.AuthorizedRawProfileContext(
        bound_profile=profile, profile_home=home, auth_session_id="tok-1"
    )


def _save_workspace(iso, ctx, path: Path) -> None:
    """Register *path* in the authorized profile's saved-workspace list."""
    state_dir = iso.state if ctx.bound_profile == "default" else ctx.profile_home / "webui_state"
    ws_file = state_dir / "workspaces.json"
    existing = []
    if ws_file.exists():
        existing = json.loads(ws_file.read_text(encoding="utf-8"))
    existing.append({"path": str(path), "name": path.name})
    _write(ws_file, json.dumps(existing))


def _write_config(ctx, cfg: dict) -> None:
    import yaml

    _write(ctx.profile_home / "config.yaml", yaml.safe_dump(cfg))


# ── Query parsing (§4) ──────────────────────────────────────────────────────


class TestQueryParsing:
    def test_valid_source_only(self):
        r = ms.parse_raw_query("source=memory")
        assert r.ok and r.source == "memory" and r.session_id is None

    def test_all_four_selectors(self):
        for name in ("memory", "user", "soul", "project_context"):
            r = ms.parse_raw_query(f"source={name}")
            assert r.ok and r.source == name

    def test_project_context_with_session_id(self):
        r = ms.parse_raw_query("source=project_context&session_id=abc-123_XYZ")
        assert r.ok and r.session_id == "abc-123_XYZ"

    def test_session_id_only_valid_for_project_context(self):
        r = ms.parse_raw_query("source=memory&session_id=abc")
        assert not r.ok

    def test_missing_source(self):
        assert not ms.parse_raw_query("").ok
        assert not ms.parse_raw_query("session_id=abc").ok

    def test_duplicate_source(self):
        assert not ms.parse_raw_query("source=memory&source=user").ok

    def test_duplicate_decoded_names(self):
        assert not ms.parse_raw_query("source=memory&%73ource=user").ok

    def test_unknown_fields_rejected(self):
        for qs in (
            "source=memory&path=/etc/passwd",
            "source=memory&filename=MEMORY.md",
            "source=memory&workspace=/tmp/x",
            "source=memory&profile=alice",
            "source=memory&file=MEMORY.md",
            "source=memory&session=MEMORY.md",
            "source=memory&foo=bar",
            "source=memory&source%5B%5D=memory",
        ):
            assert not ms.parse_raw_query(qs).ok, qs

    def test_traversal_like_input_rejected(self):
        for qs in (
            "source=../memory",
            "source=memory&session_id=../../x",
            "source=%2e%2e%2fmemory",
            "source=memory/../user",
        ):
            assert not ms.parse_raw_query(qs).ok, qs

    def test_literal_plus_and_percent_2b(self):
        # A literal '+' must stay '+' (never a space); both forms fail the grammar.
        assert not ms.parse_raw_query("source=memory+user").ok
        assert not ms.parse_raw_query("source=%2Bmemory").ok
        assert not ms.parse_raw_query("source=memory&session_id=a+b").ok

    def test_malformed_percent_escapes(self):
        for qs in (
            "source=%zz",
            "source=%2",
            "source=%",
            "source=mem%2",
        ):
            assert not ms.parse_raw_query(qs).ok, qs

    def test_invalid_utf8_and_control_characters(self):
        assert not ms.parse_raw_query("source=%FF").ok
        assert not ms.parse_raw_query("source=memory%00").ok
        assert not ms.parse_raw_query("source=%00memory").ok
        assert not ms.parse_raw_query("source=memory%01").ok

    def test_fields_without_equals_and_empty_values(self):
        assert not ms.parse_raw_query("source=memory&junk").ok
        assert not ms.parse_raw_query("source=").ok
        assert not ms.parse_raw_query("source=memory&session_id=").ok
        assert not ms.parse_raw_query("=memory").ok

    def test_encoded_source_value_equals_literal(self):
        r = ms.parse_raw_query("source=%6demory")
        assert r.ok and r.source == "memory"

    def test_session_id_grammar_and_length(self):
        assert ms.parse_raw_query("source=project_context&session_id=" + "a" * 256).ok
        assert not ms.parse_raw_query("source=project_context&session_id=" + "a" * 257).ok
        assert not ms.parse_raw_query("source=project_context&session_id=bad/id").ok
        assert not ms.parse_raw_query("source=project_context&session_id=bad%2Fid").ok
        assert not ms.parse_raw_query("source=project_context&session_id=a.b").ok
        assert not ms.parse_raw_query("source=project_context&session_id=").ok


# ── Provenance validation (§8) ──────────────────────────────────────────────


class TestProvenanceValidation:
    def test_native_no_browser_metadata(self):
        r = ms.validate_provenance([("Host", "example.test")])
        assert r.ok and r.origin == "http://example.test"

    def test_browser_same_origin(self):
        fields = [
            ("Host", "example.test"),
            ("Origin", "https://example.test"),
            ("Referer", "https://example.test/memory"),
            ("Sec-Fetch-Site", "same-origin"),
            ("Sec-Fetch-Mode", "cors"),
            ("Sec-Fetch-Dest", "empty"),
        ]
        r = ms.validate_provenance(fields, tls=True)
        assert r.ok and r.origin == "https://example.test"

    def test_duplicate_host_rejected(self):
        fields = [("Host", "example.test"), ("Host", "example.test")]
        assert not ms.validate_provenance(fields).ok

    def test_missing_and_empty_host_rejected(self):
        assert not ms.validate_provenance([]).ok
        assert not ms.validate_provenance([("Host", "")]).ok
        assert not ms.validate_provenance([("Host", "   ")]).ok

    def test_list_and_whitespace_host_rejected(self):
        assert not ms.validate_provenance([("Host", "a.test,b.test")]).ok
        assert not ms.validate_provenance([("Host", "a.test b.test")]).ok

    def test_host_userinfo_path_query_rejected(self):
        assert not ms.validate_provenance([("Host", "user@example.test")]).ok
        assert not ms.validate_provenance([("Host", "example.test/path")]).ok
        assert not ms.validate_provenance([("Host", "example.test?x=1")]).ok

    def test_host_case_normalized(self):
        r = ms.validate_provenance([("Host", "EXAMPLE.Test")])
        assert r.ok and r.origin == "http://example.test"

    def test_explicit_default_port_equals_implicit(self):
        r = ms.validate_provenance(
            [("Host", "example.test:80"), ("Origin", "http://example.test")], tls=False
        )
        assert r.ok
        r2 = ms.validate_provenance(
            [("Host", "example.test"), ("Origin", "http://example.test:80")], tls=False
        )
        assert r2.ok

    def test_non_default_port_must_match(self):
        r = ms.validate_provenance(
            [("Host", "example.test:8080"), ("Origin", "http://example.test:8080")]
        )
        assert r.ok and r.origin == "http://example.test:8080"
        assert not ms.validate_provenance(
            [("Host", "example.test:8080"), ("Origin", "http://example.test")]
        ).ok

    def test_ipv6_bracketed_host(self):
        r = ms.validate_provenance(
            [("Host", "[::1]:8080"), ("Origin", "http://[::1]:8080")]
        )
        assert r.ok and r.origin == "http://[::1]:8080"
        # A bare bracketed IPv6 host with no browser metadata is a native request.
        assert ms.validate_provenance([("Host", "[::1]:8080")]).ok
        assert not ms.validate_provenance([("Host", "[::1]:8080"), ("Origin", "http://[::1]")]).ok

    def test_origin_mismatch_rejected(self):
        fields = [("Host", "example.test"), ("Origin", "https://evil.test")]
        assert not ms.validate_provenance(fields, tls=True).ok

    def test_referer_mismatch_rejected(self):
        fields = [("Host", "example.test"), ("Referer", "https://evil.test/x")]
        assert not ms.validate_provenance(fields, tls=True).ok

    def test_origin_null_and_malformed_rejected(self):
        assert not ms.validate_provenance([("Host", "example.test"), ("Origin", "null")]).ok
        assert not ms.validate_provenance([("Host", "example.test"), ("Origin", "example.test")]).ok
        assert not ms.validate_provenance([("Host", "example.test"), ("Origin", "ftp://example.test")]).ok
        assert not ms.validate_provenance([("Host", "example.test"), ("Origin", "https://user@example.test")]).ok
        assert not ms.validate_provenance([("Host", "example.test"), ("Origin", "https://example.test/path")]).ok

    def test_duplicate_origin_and_referer_rejected(self):
        assert not ms.validate_provenance(
            [("Host", "example.test"), ("Origin", "http://example.test"), ("Origin", "http://example.test")]
        ).ok
        assert not ms.validate_provenance(
            [("Host", "example.test"), ("Referer", "http://example.test/x"), ("Referer", "http://example.test/y")]
        ).ok

    def test_fetch_metadata_without_site_rejected(self):
        fields = [
            ("Host", "example.test"),
            ("Sec-Fetch-Mode", "cors"),
            ("Sec-Fetch-Dest", "empty"),
        ]
        assert not ms.validate_provenance(fields).ok

    def test_unknown_fetch_header_rejected(self):
        fields = [
            ("Host", "example.test"),
            ("Sec-Fetch-Site", "same-origin"),
            ("Sec-Fetch-Mode", "cors"),
            ("Sec-Fetch-Dest", "empty"),
            ("Sec-Fetch-User", "?1"),
        ]
        assert not ms.validate_provenance(fields).ok

    def test_non_same_origin_site_values_rejected(self):
        for value in ("cross-site", "same-site", "none", ""):
            fields = [("Host", "example.test"), ("Sec-Fetch-Site", value)]
            assert not ms.validate_provenance(fields).ok, value

    def test_mode_and_dest_values_enforced(self):
        assert not ms.validate_provenance(
            [("Host", "example.test"), ("Sec-Fetch-Site", "same-origin"), ("Sec-Fetch-Mode", "navigate")]
        ).ok
        assert not ms.validate_provenance(
            [("Host", "example.test"), ("Sec-Fetch-Site", "same-origin"), ("Sec-Fetch-Dest", "document")]
        ).ok
        assert ms.validate_provenance(
            [("Host", "example.test"), ("Sec-Fetch-Site", "same-origin"), ("Sec-Fetch-Mode", "same-origin"), ("Sec-Fetch-Dest", "empty")]
        ).ok

    def test_duplicate_sec_fetch_field_rejected(self):
        assert not ms.validate_provenance(
            [("Host", "example.test"), ("Sec-Fetch-Site", "same-origin"), ("Sec-Fetch-Site", "same-origin")]
        ).ok

    def test_forwarded_ignored_when_disabled(self):
        fields = [
            ("Host", "example.test"),
            ("X-Forwarded-Host", "evil.test"),
            ("X-Forwarded-Proto", "http"),
        ]
        r = ms.validate_provenance(fields, trust_forwarded_host=False, trust_forwarded_proto=False)
        assert r.ok and r.origin == "http://example.test"

    def test_forwarded_proto_when_enabled(self):
        fields = [("Host", "example.test"), ("X-Forwarded-Proto", "https")]
        r = ms.validate_provenance(fields, trust_forwarded_proto=True)
        assert r.ok and r.origin == "https://example.test"

    def test_malformed_forwarded_fails_closed_when_enabled(self):
        fields = [("Host", "example.test"), ("X-Forwarded-Host", "example.test,evil.test"), ("X-Forwarded-Proto", "https")]
        assert not ms.validate_provenance(fields, trust_forwarded_host=True, trust_forwarded_proto=True).ok
        assert not ms.validate_provenance(
            [("Host", "example.test"), ("X-Forwarded-Proto", "http,https")], trust_forwarded_proto=True
        ).ok
        assert not ms.validate_provenance(
            [("Host", "example.test"), ("X-Forwarded-Proto", "ftp")], trust_forwarded_proto=True
        ).ok
        assert not ms.validate_provenance(
            [("Host", "example.test"), ("X-Forwarded-Host", "evil.test"), ("X-Forwarded-Host", "evil.test")],
            trust_forwarded_host=True,
        ).ok

    def test_fixture_provenance_vectors(self):
        """§13 — every provenance vector produces exactly its fixture status."""
        tls_for = {"browser_same_origin": True}
        for case in _FIXTURE["provenance_cases"]:
            fields = [(h, v) for h, v in case["headers"]]
            result = ms.validate_provenance(
                fields,
                tls=tls_for.get(case["id"], False),
                trust_forwarded_proto=bool(case.get("trust_forwarded_proto", False)),
                trust_forwarded_host=bool(case.get("trust_forwarded_host", False)),
            )
            expected = case["status"] == 200
            assert result.ok == expected, (
                f"provenance case {case['id']}: expected {case['status']}, got ok={result.ok}"
            )


# ── Profile config snapshot and feature gates (§9) ──────────────────────────


class TestProfileConfigSnapshot:
    def test_missing_config_maps_to_empty_snapshot(self, iso_state):
        assert ms.read_only_profile_config_snapshot(_ctx(iso_state)) == {}

    def test_reads_config_yaml_directly(self, iso_state):
        ctx = _ctx(iso_state)
        _write_config(ctx, {"memory": {"memory_enabled": False}, "workspace": "/tmp/ws"})
        snap = ms.read_only_profile_config_snapshot(ctx)
        assert snap["memory"] == {"memory_enabled": False}
        assert snap["workspace"] == "/tmp/ws"

    def test_malformed_yaml_maps_to_empty(self, iso_state):
        ctx = _ctx(iso_state)
        _write(ctx.profile_home / "config.yaml", "key: [unclosed")
        assert ms.read_only_profile_config_snapshot(ctx) == {}

    def test_non_mapping_yaml_maps_to_empty(self, iso_state):
        ctx = _ctx(iso_state)
        _write(ctx.profile_home / "config.yaml", "- a\n- b\n")
        assert ms.read_only_profile_config_snapshot(ctx) == {}

    @requires_symlink
    def test_symlinked_config_fails_closed(self, iso_state):
        ctx = _ctx(iso_state)
        ctx.profile_home.mkdir(parents=True)
        _write(iso_state.root / "real-config.yaml", "memory: {memory_enabled: false}\n")
        (ctx.profile_home / "config.yaml").symlink_to(iso_state.root / "real-config.yaml")
        assert ms.read_only_profile_config_snapshot(ctx) == {}

    def test_oversized_config_fails_closed(self, iso_state, monkeypatch):
        ctx = _ctx(iso_state)
        _write(ctx.profile_home / "config.yaml", "a: " + "x" * 200000)
        monkeypatch.setattr(ms, "CONFIG_MAX_BYTES", 1024)
        assert ms.read_only_profile_config_snapshot(ctx) == {}


class TestFeatureGates:
    def test_memory_gate_defaults_enabled(self, iso_state):
        assert ms.source_feature_gate(_ctx(iso_state), "memory") is None
        assert ms.source_feature_gate(_ctx(iso_state), "user") is None

    def test_memory_enabled_false_forbids_memory_only(self, iso_state):
        ctx = _ctx(iso_state)
        _write_config(ctx, {"memory": {"memory_enabled": False}})
        assert ms.source_feature_gate(ctx, "memory") == "forbidden"
        assert ms.source_feature_gate(ctx, "user") is None
        assert ms.source_feature_gate(ctx, "soul") is None
        assert ms.source_feature_gate(ctx, "project_context") is None

    def test_user_profile_enabled_false_forbids_user_only(self, iso_state):
        ctx = _ctx(iso_state)
        _write_config(ctx, {"memory": {"user_profile_enabled": False}})
        assert ms.source_feature_gate(ctx, "user") == "forbidden"
        assert ms.source_feature_gate(ctx, "memory") is None

    def test_soul_not_controlled_by_flags(self, iso_state):
        ctx = _ctx(iso_state)
        _write_config(ctx, {"memory": {"memory_enabled": False, "user_profile_enabled": False}})
        assert ms.source_feature_gate(ctx, "soul") is None

    def test_truthy_string_values_respected(self, iso_state):
        ctx = _ctx(iso_state)
        _write_config(ctx, {"memory": {"memory_enabled": "false"}})
        assert ms.source_feature_gate(ctx, "memory") == "forbidden"
        ctx2 = _ctx(iso_state, profile="bob")
        _write_config(ctx2, {"memory": {"memory_enabled": "true"}})
        assert ms.source_feature_gate(ctx2, "memory") is None


# ── Default workspace resolver (§9) ─────────────────────────────────────────


class TestDefaultWorkspace:
    def test_last_workspace_file_wins_for_default_profile(self, iso_state):
        ctx = _ctx(iso_state, profile="default")
        ws = iso_state.root / "ws"
        ws.mkdir()
        _write(iso_state.state / "last_workspace.txt", str(ws))
        assert ms.read_only_profile_default_workspace(ctx) == ws

    def test_named_profile_uses_own_webui_state(self, iso_state):
        ctx = _ctx(iso_state)
        ws = iso_state.root / "ws"
        ws.mkdir()
        _write(ctx.profile_home / "webui_state" / "last_workspace.txt", str(ws))
        # A default-profile STATE_DIR entry must not leak into the named profile.
        _write(iso_state.state / "last_workspace.txt", str(iso_state.root / "other"))
        assert ms.read_only_profile_default_workspace(ctx) == ws

    def test_config_keys_precedence(self, iso_state):
        ctx = _ctx(iso_state)
        a, b, c = (iso_state.root / n for n in ("a", "b", "c"))
        for d in (a, b, c):
            d.mkdir()
        _write_config(ctx, {"workspace": str(a), "default_workspace": str(b), "terminal": {"cwd": str(c)}})
        assert ms.read_only_profile_default_workspace(ctx) == a

    def test_default_workspace_then_terminal_cwd(self, iso_state):
        ctx = _ctx(iso_state)
        b, c = (iso_state.root / n for n in ("b", "c"))
        b.mkdir()
        c.mkdir()
        _write_config(ctx, {"default_workspace": str(b), "terminal": {"cwd": str(c)}})
        assert ms.read_only_profile_default_workspace(ctx) == b
        ctx2 = _ctx(iso_state, profile="bob")
        c2 = iso_state.root / "c2"
        c2.mkdir()
        _write_config(ctx2, {"terminal": {"cwd": str(c2)}})
        assert ms.read_only_profile_default_workspace(ctx2) == c2

    def test_missing_all_returns_none(self, iso_state):
        assert ms.read_only_profile_default_workspace(_ctx(iso_state)) is None

    def test_non_directory_candidate_returns_none(self, iso_state):
        ctx = _ctx(iso_state)
        f = iso_state.root / "file"
        _write(f, "x")
        _write_config(ctx, {"workspace": str(f)})
        assert ms.read_only_profile_default_workspace(ctx) is None

    def test_empty_last_workspace_falls_through_to_config(self, iso_state):
        ctx = _ctx(iso_state)
        ws = iso_state.root / "ws"
        ws.mkdir()
        _write(ctx.profile_home / "webui_state" / "last_workspace.txt", "   \n")
        _write_config(ctx, {"workspace": str(ws)})
        assert ms.read_only_profile_default_workspace(ctx) == ws

    def test_remote_terminal_backend_returns_none(self, iso_state):
        ctx = _ctx(iso_state)
        ws = iso_state.root / "ws"
        ws.mkdir()
        _write_config(ctx, {"workspace": str(ws), "terminal": {"backend": "ssh", "cwd": str(ws)}})
        assert ms.read_only_profile_default_workspace(ctx) is None


# ── Read-only session metadata (§9) ─────────────────────────────────────────


class TestSessionMetadata:
    def _sidecar(self, iso_state, sid, payload):
        _write(iso_state.state / "sessions" / f"{sid}.json", json.dumps(payload))

    def test_valid_sidecar(self, iso_state):
        ctx = _ctx(iso_state)
        self._sidecar(
            iso_state, "sess-1",
            {"session_id": "sess-1", "workspace": "/tmp/ws", "profile": "alice", "messages": []},
        )
        meta = ms.read_only_session_metadata(ctx, "sess-1")
        assert meta == {"workspace": "/tmp/ws", "profile": "alice"}

    def test_missing_profile_is_root_alias(self, iso_state):
        ctx = _ctx(iso_state, profile="default")
        self._sidecar(iso_state, "sess-1", {"session_id": "sess-1", "workspace": "/tmp/ws"})
        assert ms.read_only_session_metadata(ctx, "sess-1") == {"workspace": "/tmp/ws", "profile": "default"}
        self._sidecar(iso_state, "sess-2", {"session_id": "sess-2", "workspace": "/tmp/ws", "profile": ""})
        assert ms.read_only_session_metadata(ctx, "sess-2") == {"workspace": "/tmp/ws", "profile": "default"}

    def test_foreign_profile_rejected(self, iso_state):
        ctx = _ctx(iso_state)  # alice
        self._sidecar(iso_state, "sess-1", {"session_id": "sess-1", "workspace": "/tmp/ws", "profile": "bob"})
        assert ms.read_only_session_metadata(ctx, "sess-1") is None

    def test_blank_workspace_rejected(self, iso_state):
        ctx = _ctx(iso_state)
        self._sidecar(iso_state, "sess-1", {"session_id": "sess-1", "workspace": "", "profile": "alice"})
        assert ms.read_only_session_metadata(ctx, "sess-1") is None
        self._sidecar(iso_state, "sess-2", {"session_id": "sess-2", "profile": "alice"})
        assert ms.read_only_session_metadata(ctx, "sess-2") is None

    def test_malformed_and_missing_sidecars(self, iso_state):
        ctx = _ctx(iso_state)
        assert ms.read_only_session_metadata(ctx, "sess-1") is None
        _write(iso_state.state / "sessions" / "sess-1.json", "{not json")
        assert ms.read_only_session_metadata(ctx, "sess-1") is None
        _write(iso_state.state / "sessions" / "sess-1.json", "[1,2]")
        assert ms.read_only_session_metadata(ctx, "sess-1") is None

    def test_unsafe_session_id_grammar(self, iso_state):
        ctx = _ctx(iso_state)
        for sid in ("../x", "a/b", "a b", "", "a.b", "a\\b", "x" * 257):
            assert ms.read_only_session_metadata(ctx, sid) is None, sid

    @requires_symlink
    def test_symlinked_sidecar_fails_closed(self, iso_state):
        ctx = _ctx(iso_state)
        _write(iso_state.root / "real.json", json.dumps({"workspace": "/tmp/ws", "profile": "alice"}))
        (iso_state.state / "sessions").mkdir(parents=True)
        (iso_state.state / "sessions" / "sess-1.json").symlink_to(iso_state.root / "real.json")
        assert ms.read_only_session_metadata(ctx, "sess-1") is None

    def test_over_cap_sidecar_fails_closed(self, iso_state, monkeypatch):
        ctx = _ctx(iso_state)
        payload = {"workspace": "/tmp/ws", "profile": "alice", "messages": [{"x": "y" * 2000}] * 100}
        self._sidecar(iso_state, "sess-1", payload)
        monkeypatch.setattr(ms, "SESSION_METADATA_MAX_BYTES", 1024)
        assert ms.read_only_session_metadata(ctx, "sess-1") is None

    def test_messages_never_parsed_for_recovery(self, iso_state):
        # workspace/profile live in the bounded prefix; a huge messages array is ignored.
        ctx = _ctx(iso_state)
        payload = {
            "session_id": "sess-1",
            "workspace": "/tmp/ws",
            "profile": "alice",
            "messages": [{"role": "user", "content": "x" * 1000} for _ in range(50)],
        }
        self._sidecar(iso_state, "sess-1", payload)
        assert ms.read_only_session_metadata(ctx, "sess-1") == {"workspace": "/tmp/ws", "profile": "alice"}


# ── Trusted workspace resolver (§9) ─────────────────────────────────────────


class TestTrustedWorkspace:
    def test_under_home_is_trusted(self, iso_state, monkeypatch):
        ctx = _ctx(iso_state)
        home = iso_state.root / "home"
        ws = home / "proj"
        ws.mkdir(parents=True)
        monkeypatch.setattr(ms, "_home_dir", lambda: home)
        assert ms.read_only_resolve_trusted_workspace(ctx, ws) == ws

    def test_saved_workspace_is_trusted_outside_home(self, iso_state, monkeypatch):
        ctx = _ctx(iso_state)
        home = iso_state.root / "home"
        home.mkdir()
        ws = iso_state.root / "data" / "proj"
        ws.mkdir(parents=True)
        monkeypatch.setattr(ms, "_home_dir", lambda: home)
        _save_workspace(iso_state, ctx, ws)
        assert ms.read_only_resolve_trusted_workspace(ctx, ws) == ws

    def test_untrusted_outside_home_rejected(self, iso_state, monkeypatch):
        ctx = _ctx(iso_state)
        home = iso_state.root / "home"
        home.mkdir()
        ws = iso_state.root / "data" / "proj"
        ws.mkdir(parents=True)
        monkeypatch.setattr(ms, "_home_dir", lambda: home)
        assert ms.read_only_resolve_trusted_workspace(ctx, ws) is None

    def test_system_root_rejected_even_when_saved(self, iso_state, monkeypatch):
        ctx = _ctx(iso_state)
        home = iso_state.root / "home"
        home.mkdir()
        monkeypatch.setattr(ms, "_home_dir", lambda: home)
        for root in ("/etc", "/usr", "/bin", "/var", "/proc", "/sys", "/dev"):
            if Path(root).exists():
                _save_workspace(iso_state, ctx, Path(root))
                assert ms.read_only_resolve_trusted_workspace(ctx, Path(root)) is None, root

    def test_missing_non_dir_empty_candidates_rejected(self, iso_state, monkeypatch):
        ctx = _ctx(iso_state)
        home = iso_state.root / "home"
        home.mkdir()
        monkeypatch.setattr(ms, "_home_dir", lambda: home)
        assert ms.read_only_resolve_trusted_workspace(ctx, None) is None
        assert ms.read_only_resolve_trusted_workspace(ctx, "") is None
        assert ms.read_only_resolve_trusted_workspace(ctx, iso_state.root / "missing") is None
        f = iso_state.root / "file"
        _write(f, "x")
        assert ms.read_only_resolve_trusted_workspace(ctx, f) is None

    def test_remote_terminal_candidate_rejected(self, iso_state, monkeypatch):
        ctx = _ctx(iso_state)
        home = iso_state.root / "home"
        ws = iso_state.root / "proj"
        ws.mkdir(parents=True)
        home.mkdir()
        monkeypatch.setattr(ms, "_home_dir", lambda: home)
        _write_config(ctx, {"terminal": {"backend": "ssh", "cwd": str(ws)}})
        assert ms.read_only_resolve_trusted_workspace(ctx, ws) is None

    def test_malformed_workspaces_json_fails_closed(self, iso_state, monkeypatch):
        ctx = _ctx(iso_state)
        home = iso_state.root / "home"
        home.mkdir()
        ws = iso_state.root / "data" / "proj"
        ws.mkdir(parents=True)
        monkeypatch.setattr(ms, "_home_dir", lambda: home)
        _write(iso_state.state / "workspaces.json", "{broken")
        assert ms.read_only_resolve_trusted_workspace(ctx, ws) is None


# ── Fixed source resolution (§9) ────────────────────────────────────────────


class TestFixedSourceResolution:
    def test_memory_user_soul_mappings(self, iso_state):
        ctx = _ctx(iso_state)
        res = ms.resolve_fixed_source(ctx, "memory")
        assert res.ok
        assert (res.anchor, res.components, res.name, res.content_type) == (
            ctx.profile_home, ("memories", "MEMORY.md"), "MEMORY.md", "text/markdown",
        )
        res = ms.resolve_fixed_source(ctx, "user")
        assert (res.anchor, res.components, res.name, res.content_type) == (
            ctx.profile_home, ("memories", "USER.md"), "USER.md", "text/markdown",
        )
        res = ms.resolve_fixed_source(ctx, "soul")
        assert (res.anchor, res.components, res.name, res.content_type) == (
            ctx.profile_home, ("SOUL.md",), "SOUL.md", "text/markdown",
        )

    def test_disabled_gates_return_forbidden(self, iso_state):
        ctx = _ctx(iso_state)
        _write_config(ctx, {"memory": {"memory_enabled": False, "user_profile_enabled": False}})
        assert ms.resolve_fixed_source(ctx, "memory").error == "forbidden"
        assert ms.resolve_fixed_source(ctx, "user").error == "forbidden"
        assert ms.resolve_fixed_source(ctx, "soul").ok

    def test_project_context_default_workspace(self, iso_state, monkeypatch):
        ctx = _ctx(iso_state)
        ws = iso_state.root / "proj"
        ws.mkdir(parents=True)
        _save_workspace(iso_state, ctx, ws)
        _write_config(ctx, {"workspace": str(ws)})
        _write(ws / ".hermes.md", b"# P\n")
        res = ms.resolve_fixed_source(ctx, "project_context")
        assert res.ok and res.anchor == ws and res.components == (".hermes.md",) and res.name == ".hermes.md"

    def test_project_context_invalid_default_workspace_not_found(self, iso_state):
        ctx = _ctx(iso_state)
        _write_config(ctx, {"workspace": str(iso_state.root / "missing")})
        assert ms.resolve_fixed_source(ctx, "project_context").error == "not_found"

    def test_project_context_session_workspace(self, iso_state):
        ctx = _ctx(iso_state)
        ws = iso_state.root / "proj"
        ws.mkdir(parents=True)
        _save_workspace(iso_state, ctx, ws)
        _write(ws / ".hermes.md", b"# P\n")
        _write(
            iso_state.state / "sessions" / "sess-1.json",
            json.dumps({"session_id": "sess-1", "workspace": str(ws), "profile": "alice"}),
        )
        res = ms.resolve_fixed_source(ctx, "project_context", session_id="sess-1")
        assert res.ok and res.anchor == ws and res.components == (".hermes.md",)

    def test_project_context_session_not_found(self, iso_state):
        ctx = _ctx(iso_state)
        assert ms.resolve_fixed_source(ctx, "project_context", session_id="nope").error == "not_found"

    def test_project_context_session_untrusted_workspace_not_found(self, iso_state):
        ctx = _ctx(iso_state)
        ws = iso_state.root / "proj"
        ws.mkdir(parents=True)  # exists but never saved/trusted
        _write(
            iso_state.state / "sessions" / "sess-1.json",
            json.dumps({"session_id": "sess-1", "workspace": str(ws), "profile": "alice"}),
        )
        assert ms.resolve_fixed_source(ctx, "project_context", session_id="sess-1").error == "not_found"

    def test_unknown_source_is_invalid(self, iso_state):
        assert ms.resolve_fixed_source(_ctx(iso_state), "notes").error == "invalid_request"


class TestProjectCandidateOrder:
    """§9 — workspace-first ascending to the authorized Git root; fixed names."""

    def _setup(self, iso_state, monkeypatch, *, git_root_authorized):
        ctx = _ctx(iso_state)
        ws = iso_state.root / "repo" / "sub"
        ws.mkdir(parents=True)
        monkeypatch.setattr(ms, "_home_dir", lambda: iso_state.root / "home")
        _save_workspace(iso_state, ctx, ws)
        if git_root_authorized:
            _save_workspace(iso_state, ctx, iso_state.root / "repo")
        (iso_state.root / "repo" / ".git").mkdir()
        _write_config(ctx, {"workspace": str(ws)})
        return ctx, ws

    def test_workspace_candidate_beats_root_candidate(self, iso_state, monkeypatch):
        ctx, ws = self._setup(iso_state, monkeypatch, git_root_authorized=True)
        _write(ws / ".hermes.md", "# ws\n")
        _write(iso_state.root / "repo" / ".hermes.md", "# root\n")
        res = ms.resolve_fixed_source(ctx, "project_context")
        assert res.ok and res.anchor == iso_state.root / "repo"
        assert res.components == ("sub", ".hermes.md")
        assert res.name == ".hermes.md"

    def test_hermes_md_after_hermes_md_dot(self, iso_state, monkeypatch):
        ctx, ws = self._setup(iso_state, monkeypatch, git_root_authorized=True)
        _write(ws / "HERMES.md", "# H\n")
        _write(iso_state.root / "repo" / ".hermes.md", "# root\n")
        res = ms.resolve_fixed_source(ctx, "project_context")
        assert res.components == ("sub", "HERMES.md")

    def test_ascending_walk_reaches_authorized_root(self, iso_state, monkeypatch):
        ctx, ws = self._setup(iso_state, monkeypatch, git_root_authorized=True)
        _write(iso_state.root / "repo" / "HERMES.md", "# root H\n")
        res = ms.resolve_fixed_source(ctx, "project_context")
        assert res.ok and res.components == ("HERMES.md",)
        assert res.anchor == iso_state.root / "repo"

    def test_unauthorized_git_root_restricts_scan(self, iso_state, monkeypatch):
        ctx, ws = self._setup(iso_state, monkeypatch, git_root_authorized=False)
        _write(iso_state.root / "repo" / ".hermes.md", "# root\n")
        assert ms.resolve_fixed_source(ctx, "project_context").error == "not_found"

    def test_trusted_level_fallback_names(self, iso_state, monkeypatch):
        ctx, ws = self._setup(iso_state, monkeypatch, git_root_authorized=True)
        for name in ("AGENTS.md", "agents.md", "CLAUDE.md", "claude.md", ".cursorrules"):
            _write(ws / name, f"# {name}\n")
        res = ms.resolve_fixed_source(ctx, "project_context")
        assert res.name == "AGENTS.md" and res.components == ("sub", "AGENTS.md")
        # Remove each winner in turn; the fixed order is agents.md, CLAUDE.md,
        # claude.md, then .cursorrules.
        for expected in ("agents.md", "CLAUDE.md", "claude.md"):
            (ws / res.name).unlink()
            res = ms.resolve_fixed_source(ctx, "project_context")
            assert res.name == expected, expected
        (ws / res.name).unlink()
        res = ms.resolve_fixed_source(ctx, "project_context")
        assert res.name == ".cursorrules"

    def test_cursor_rules_mdc_sorted(self, iso_state, monkeypatch):
        ctx, ws = self._setup(iso_state, monkeypatch, git_root_authorized=True)
        rules = ws / ".cursor" / "rules"
        rules.mkdir(parents=True)
        _write(rules / "b.mdc", "# b\n")
        _write(rules / "a.mdc", "# a\n")
        _write(rules / "c.txt", "not mdc\n")
        res = ms.resolve_fixed_source(ctx, "project_context")
        assert res.name == "a.mdc"
        assert res.components == ("sub", ".cursor", "rules", "a.mdc")
        assert res.content_type == "text/markdown"

    def test_cursor_rules_regular_file_only(self, iso_state, monkeypatch):
        ctx, ws = self._setup(iso_state, monkeypatch, git_root_authorized=True)
        rules = ws / ".cursor" / "rules"
        rules.mkdir(parents=True)
        (rules / "d.mdc").mkdir()  # directory named *.mdc — not a regular file
        _write(rules / "c.mdc", "# c\n")
        res = ms.resolve_fixed_source(ctx, "project_context")
        assert res.name == "c.mdc"

    def test_no_candidate_not_found(self, iso_state, monkeypatch):
        ctx, ws = self._setup(iso_state, monkeypatch, git_root_authorized=True)
        assert ms.resolve_fixed_source(ctx, "project_context").error == "not_found"

    def test_missing_default_workspace_not_found(self, iso_state, monkeypatch):
        ctx, _ws = self._setup(iso_state, monkeypatch, git_root_authorized=True)
        # Remove the config so the default workspace is missing.
        (ctx.profile_home / "config.yaml").unlink()
        assert ms.resolve_fixed_source(ctx, "project_context").error == "not_found"

    @requires_symlink
    def test_symlinked_candidate_not_selected(self, iso_state, monkeypatch):
        ctx, ws = self._setup(iso_state, monkeypatch, git_root_authorized=True)
        _write(iso_state.root / "outside.md", "# outside\n")
        (ws / ".hermes.md").symlink_to(iso_state.root / "outside.md")
        assert ms.resolve_fixed_source(ctx, "project_context").error == "not_found"


# ── Anchored bounded reader (§10) ───────────────────────────────────────────


class TestAnchoredReader:
    def test_reads_regular_file(self, iso_state):
        ctx = _ctx(iso_state)
        _write(ctx.profile_home / "memories" / "MEMORY.md", b"# Note\nline\n")
        res = ms.read_anchored_source(ctx.profile_home, ("memories", "MEMORY.md"), 1000)
        assert res.status == 200 and res.data == b"# Note\nline\n"

    def test_byte_faithful_invalid_utf8_round_trip(self, iso_state):
        ctx = _ctx(iso_state)
        raw = b"ok\xff\xfe\x00\n\xc3\xa9"
        _write(ctx.profile_home / "SOUL.md", raw)
        res = ms.read_anchored_source(ctx.profile_home, ("SOUL.md",), 1000)
        assert res.status == 200 and res.data == raw
        assert base64.b64decode(ms.build_envelope("soul", "SOUL.md", "text/markdown", res.data)["data"]) == raw

    def test_empty_file_is_valid_zero_byte_source(self, iso_state):
        ctx = _ctx(iso_state)
        _write(ctx.profile_home / "SOUL.md", b"")
        res = ms.read_anchored_source(ctx.profile_home, ("SOUL.md",), 1000)
        assert res.status == 200 and res.data == b""

    def test_missing_source_404(self, iso_state):
        ctx = _ctx(iso_state)
        res = ms.read_anchored_source(ctx.profile_home, ("SOUL.md",), 1000)
        assert res.status == 404 and res.error == "not_found"

    def test_directory_final_component_404(self, iso_state):
        ctx = _ctx(iso_state)
        (ctx.profile_home / "memories").mkdir(parents=True)
        res = ms.read_anchored_source(ctx.profile_home, ("memories",), 1000)
        assert res.status == 404

    def test_fifo_final_component_404(self, iso_state):
        ctx = _ctx(iso_state)
        fifo = ctx.profile_home / "SOUL.md"
        fifo.parent.mkdir(parents=True, exist_ok=True)
        os.mkfifo(fifo)
        res = ms.read_anchored_source(ctx.profile_home, ("SOUL.md",), 1000)
        assert res.status == 404

    @requires_symlink
    def test_symlinked_final_component_404(self, iso_state):
        ctx = _ctx(iso_state)
        _write(iso_state.root / "real.md", b"x")
        ctx.profile_home.mkdir(parents=True)
        (ctx.profile_home / "SOUL.md").symlink_to(iso_state.root / "real.md")
        res = ms.read_anchored_source(ctx.profile_home, ("SOUL.md",), 1000)
        assert res.status == 404

    @requires_symlink
    def test_symlinked_intermediate_component_404(self, iso_state):
        ctx = _ctx(iso_state)
        _write(iso_state.root / "real" / "MEMORY.md", b"x")
        ctx.profile_home.mkdir(parents=True)
        (ctx.profile_home / "memories").symlink_to(iso_state.root / "real")
        res = ms.read_anchored_source(ctx.profile_home, ("memories", "MEMORY.md"), 1000)
        assert res.status == 404

    def test_malformed_components_fail_closed(self, iso_state):
        ctx = _ctx(iso_state)
        _write(ctx.profile_home / "SOUL.md", b"x")
        for components in (("..", "SOUL.md"), ("SOUL.md", ".."), ("a/b",), ("/SOUL.md",), (".", "SOUL.md"), ("",), ("SOUL.md\x00",)):
            res = ms.read_anchored_source(ctx.profile_home, components, 1000)
            assert res.status == 404, components

    def test_invalid_limit_is_raw_unavailable(self, iso_state):
        ctx = _ctx(iso_state)
        _write(ctx.profile_home / "SOUL.md", b"x")
        for limit in (None, 0, -1, "100"):
            res = ms.read_anchored_source(ctx.profile_home, ("SOUL.md",), limit)
            assert res.status == 503 and res.error == "raw_unavailable", limit

    def test_unsupported_platform_fails_closed(self, iso_state, monkeypatch):
        ctx = _ctx(iso_state)
        _write(ctx.profile_home / "SOUL.md", b"x")
        monkeypatch.setattr(ms, "_RACE_SAFE_READ_SUPPORTED", False)
        res = ms.read_anchored_source(ctx.profile_home, ("SOUL.md",), 1000)
        assert res.status == 503 and res.error == "raw_unavailable"

    def test_short_positive_reads_continue_to_eof(self, iso_state, monkeypatch):
        ctx = _ctx(iso_state)
        raw = b"# Note\nline\nthird\n" * 10
        _write(ctx.profile_home / "SOUL.md", raw)
        real_read = os.read

        def short_read(fd, n):
            return real_read(fd, min(n, 3))  # stable regular file, tiny chunks

        monkeypatch.setattr(ms, "_raw_read", short_read)
        res = ms.read_anchored_source(ctx.profile_home, ("SOUL.md",), 10000)
        assert res.status == 200 and res.data == raw

    def test_exact_limit_success(self, iso_state):
        ctx = _ctx(iso_state)
        raw = b"a" * 1024
        _write(ctx.profile_home / "SOUL.md", raw)
        res = ms.read_anchored_source(ctx.profile_home, ("SOUL.md",), 1024)
        assert res.status == 200 and res.data == raw

    def test_limit_plus_one_is_413(self, iso_state):
        ctx = _ctx(iso_state)
        _write(ctx.profile_home / "SOUL.md", b"a" * 1025)
        res = ms.read_anchored_source(ctx.profile_home, ("SOUL.md",), 1024)
        assert res.status == 413 and res.error == "source_too_large" and res.data is None

    def test_eof_before_stable_size_is_409(self, iso_state, monkeypatch):
        ctx = _ctx(iso_state)
        target = ctx.profile_home / "SOUL.md"
        _write(target, b"a" * 100)
        real_read = os.read
        truncated = {"done": False}

        def truncating_read(fd, n):
            if not truncated["done"]:
                truncated["done"] = True
                # Shrink the file under the reader through a separate write fd.
                with open(target, "r+b") as wf:
                    wf.truncate(10)
            return real_read(fd, n)

        monkeypatch.setattr(ms, "_raw_read", truncating_read)
        res = ms.read_anchored_source(ctx.profile_home, ("SOUL.md",), 1000)
        assert res.status == 409 and res.error == "source_changed" and res.data is None

    def test_same_size_in_place_rewrite_is_409(self, iso_state, monkeypatch):
        ctx = _ctx(iso_state)
        target = ctx.profile_home / "SOUL.md"
        _write(target, b"a" * 100)
        real_read = os.read
        rewritten = {"done": False}

        def rewriting_read(fd, n):
            if not rewritten["done"]:
                rewritten["done"] = True
                # Rewrite the same inode in place (same size) through a write fd,
                # then pin a deterministic, different mtime.
                with open(target, "r+b") as wf:
                    wf.seek(0)
                    wf.write(b"b" * 100)
                    wf.flush()
                    os.fsync(wf.fileno())
                    os.utime(wf.fileno(), ns=(946684800000000000, 946684800000000000))
            return real_read(fd, n)

        monkeypatch.setattr(ms, "_raw_read", rewriting_read)
        res = ms.read_anchored_source(ctx.profile_home, ("SOUL.md",), 1000)
        assert res.status == 409 and res.error == "source_changed"

    def test_atomic_replacement_is_409(self, iso_state, monkeypatch):
        ctx = _ctx(iso_state)
        _write(ctx.profile_home / "SOUL.md", b"a" * 100)
        real_read = os.read
        replaced = {"done": False}
        target = ctx.profile_home / "SOUL.md"

        def replacing_read(fd, n):
            if not replaced["done"]:
                replaced["done"] = True
                tmp = ctx.profile_home / "SOUL.md.tmp"
                _write(tmp, b"c" * 100)
                os.replace(tmp, target)  # new inode at the same name
            return real_read(fd, n)

        monkeypatch.setattr(ms, "_raw_read", replacing_read)
        res = ms.read_anchored_source(ctx.profile_home, ("SOUL.md",), 1000)
        assert res.status == 409 and res.error == "source_changed"

    def test_anchor_replacement_is_409(self, iso_state, monkeypatch):
        ctx = _ctx(iso_state)
        _write(ctx.profile_home / "SOUL.md", b"a" * 100)
        real_read = os.read
        swapped = {"done": False}
        anchor = ctx.profile_home

        def anchor_swap_read(fd, n):
            if not swapped["done"]:
                swapped["done"] = True
                os.rename(anchor, iso_state.root / "profile-moved")  # anchor entry disappears
            return real_read(fd, n)

        monkeypatch.setattr(ms, "_raw_read", anchor_swap_read)
        res = ms.read_anchored_source(anchor, ("SOUL.md",), 1000)
        assert res.status == 409 and res.error == "source_changed"

    def test_root_anchor_refused(self, iso_state):
        res = ms.read_anchored_source(Path("/"), ("etc", "hostname"), 1000)
        assert res.status == 503 and res.error == "raw_unavailable"


# ── Envelope and canonical serializer (§11) ─────────────────────────────────


class TestEnvelope:
    def test_envelope_fields(self):
        env = ms.build_envelope("memory", "MEMORY.md", "text/markdown", b"# Note\nline\n")
        assert env["schema_version"] == 1
        assert env["source"] == "memory"
        assert env["name"] == "MEMORY.md"
        assert env["content_type"] == "text/markdown"
        assert env["byte_length"] == 12
        assert env["byte_encoding"] == "base64"
        assert env["data"] == "IyBOb3RlCmxpbmUK"
        digest = "bb89a6e8128d049f4225932f9de463fef2e992c8a439b20ebb17b3792ddac3d2"
        assert env["checksum"] == {"algorithm": "sha-256", "value": digest}
        assert env["source_version"] == f"sha256:{digest}"

    def test_no_path_or_workspace_fields(self):
        env = ms.build_envelope("project_context", "AGENTS.md", "text/markdown", b"x")
        assert "path" not in env and "workspace" not in env and "profile" not in env

    def test_standard_padded_base64(self):
        import re

        raw = b"\x00\x01\x02\xfe\xff"
        env = ms.build_envelope("memory", "MEMORY.md", "text/markdown", raw)
        assert re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", env["data"])
        assert base64.b64decode(env["data"]) == raw
        # Re-encoding must reproduce the exact padded value (canonical base64).
        assert base64.b64encode(base64.b64decode(env["data"])).decode("ascii") == env["data"]

    def test_canonical_serializer_exact_bytes(self):
        env = ms.build_envelope("memory", "MEMORY.md", "text/markdown", b"# Note\nline\n")
        body = ms.serialize_envelope(env)
        assert body == _canonical_dumps(env)
        assert not body.endswith(b"\n")
        # sort_keys + compact + ensure_ascii spot checks
        text = body.decode("utf-8")
        assert text.index('"byte_length":12') >= 0
        assert text.index('"checksum":{"algorithm":"sha-256"') >= 0
        assert '"data":"IyBOb3RlCmxpbmUK"' in text

    def test_ensure_ascii_escapes_non_ascii(self):
        # The base64 data field is always ASCII, so exercise a non-ASCII
        # metadata field (the envelope name) to prove ensure_ascii=True.
        env = ms.build_envelope("memory", "café.md", "text/markdown", b"x")
        body = ms.serialize_envelope(env)
        text = body.decode("utf-8")
        assert "caf\\u00e9.md" in text
        assert "é" not in text

    def test_representation_etag_quoted_and_distinct(self):
        raw = b"# Note\nline\n"
        env = ms.build_envelope("memory", "MEMORY.md", "text/markdown", raw)
        body = ms.serialize_envelope(env)
        etag = ms.representation_etag(body)
        digest = hashlib.sha256(body).hexdigest()
        assert etag == f'"repr-sha256:{digest}"'
        assert len(digest) == 64 and digest.islower()
        # The representation digest is over the JSON bytes, not the source bytes.
        assert digest != hashlib.sha256(raw).hexdigest()
        assert etag != f'"repr-sha256:{hashlib.sha256(raw).hexdigest()}"'

    def test_content_length_is_exact_utf8_length(self):
        env = ms.build_envelope("memory", "MEMORY.md", "text/markdown", "café".encode("utf-8"))
        body = ms.serialize_envelope(env)
        assert len(body) == len(body.decode("utf-8").encode("utf-8"))

    def test_allow_nan_never_produces_non_json(self):
        # The serializer must fail loudly (ValueError) rather than emit NaN tokens.
        env = {"schema_version": 1, "bad": float("nan")}
        with pytest.raises(ValueError):
            ms.serialize_envelope(env)


# ── Verified fixture wire contract (§13) ────────────────────────────────────


class TestFixtureWireContract:
    def test_fixture_asset_is_the_verified_embedded_fixture(self):
        assert _FIXTURE["fixture"] == "memory_raw_v1_complete_response_cases"
        assert _FIXTURE["schema_version"] == 1
        assert _FIXTURE["canonical_case_mapping"] == {
            "content_type": "text/markdown",
            "name": "MEMORY.md",
            "source": "memory",
        }
        assert [c["id"] for c in _FIXTURE["cases"]] == [
            "empty", "lf", "crlf", "lone_cr", "bom", "nul",
            "missing_final_newline", "unicode", "malformed_utf8",
        ]

    def test_fixture_contains_section13_contract_members(self):
        for key in (
            "endpoint", "headers", "if_none_match", "request_framing",
            "errors", "capability_supported", "capability_unsupported", "etag_scope",
        ):
            assert key in _FIXTURE, key
        assert _FIXTURE["endpoint"] == "/api/memory/raw"
        assert _FIXTURE["capability_supported"]["available"] is True
        assert _FIXTURE["capability_unsupported"] == {"available": False}
        assert "memory_raw_v1" not in _FIXTURE  # capability field itself is PR 2

    def test_every_byte_case_round_trips_through_the_module(self):
        for case in _FIXTURE["cases"]:
            source_bytes = base64.b64decode(case["source_base64"])
            assert len(source_bytes) == case["source_byte_length"], case["id"]
            digest = hashlib.sha256(source_bytes).hexdigest()
            assert digest == case["source_sha256"], case["id"]
            assert case["source_version"] == f"sha256:{digest}", case["id"]

            env = ms.build_envelope(
                _FIXTURE["canonical_case_mapping"]["source"],
                _FIXTURE["canonical_case_mapping"]["name"],
                _FIXTURE["canonical_case_mapping"]["content_type"],
                source_bytes,
            )
            body = ms.serialize_envelope(env)
            canonical = case["canonical_200"]

            # Chunks concatenate losslessly to the complete body base64.
            chunked = "".join(canonical["body_base64_chunks"])
            assert base64.b64decode(chunked) == body, case["id"]
            assert len(body) == canonical["body_byte_length"], case["id"]
            assert canonical["headers"]["Content-Length"] == str(len(body)), case["id"]
            assert canonical["headers"]["Content-Type"] == "application/json; charset=utf-8"
            assert canonical["headers"]["Cache-Control"] == "private, no-store"
            assert "Content-Encoding" not in canonical["headers"]
            assert "Vary" not in canonical["headers"]
            assert canonical["absent_headers"] == ["Content-Encoding", "Vary"]

            rep = hashlib.sha256(body).hexdigest()
            assert rep == canonical["representation_sha256"], case["id"]
            assert canonical["etag"] == f'"repr-sha256:{rep}"', case["id"]
            assert canonical["headers"]["ETag"] == canonical["etag"]
            # Source hashes are never reused as representation ETags.
            assert rep != case["source_sha256"], case["id"]
            assert canonical["etag"] != f'"repr-sha256:{case["source_sha256"]}"'

    def test_conditional_304_fixture_is_bodyless(self):
        c304 = _FIXTURE["conditional_304"]
        assert c304["status"] == 304
        assert c304["case_id"] == "lf"
        assert c304["body_base64"] == ""
        assert c304["trailers_absent"] is True
        assert c304["request_headers"] == {
            "If-None-Match": '"repr-sha256:8f85cc4d4f79e33cf20327f216df9ddaba87799b17c033ade0620848d24036db"'
        }
        for name in ("Content-Length", "Content-Type", "Content-Encoding", "Vary", "Trailer"):
            assert name not in c304["headers"], name
        assert c304["headers"]["ETag"] == '"repr-sha256:8f85cc4d4f79e33cf20327f216df9ddaba87799b17c033ade0620848d24036db"'
        assert c304["headers"]["Cache-Control"] == "private, no-store"

    def test_lf_case_reference_values(self):
        case = next(c for c in _FIXTURE["cases"] if c["id"] == "lf")
        assert base64.b64decode(case["source_base64"]) == b"# Note\nline\n"
        assert case["canonical_200"]["body_byte_length"] == 357
        assert case["canonical_200"]["representation_sha256"] == (
            "8f85cc4d4f79e33cf20327f216df9ddaba87799b17c033ade0620848d24036db"
        )


# ── Limit configuration and semaphore (§10) ─────────────────────────────────


class TestLimitConfiguration:
    def test_unset_defaults_to_8_mib(self, monkeypatch):
        monkeypatch.delenv("HERMES_WEBUI_MEMORY_RAW_MAX_BYTES", raising=False)
        assert ms.raw_max_bytes() == 8388608

    def test_valid_configured_values(self, monkeypatch):
        monkeypatch.setenv("HERMES_WEBUI_MEMORY_RAW_MAX_BYTES", "16777216")
        assert ms.raw_max_bytes() == 16777216
        monkeypatch.setenv("HERMES_WEBUI_MEMORY_RAW_MAX_BYTES", "1")
        assert ms.raw_max_bytes() == 1

    def test_invalid_values_return_none(self, monkeypatch):
        for bad in ("0", "-1", "+1", "1.5", "0x10", "1_000", "1e6", " 1024", "1024 ", "", "abc", "16777217", "９"):
            monkeypatch.setenv("HERMES_WEBUI_MEMORY_RAW_MAX_BYTES", bad)
            assert ms.raw_max_bytes() is None, bad

    def test_default_exact_limit_and_plus_one(self, iso_state):
        ctx = _ctx(iso_state)
        limit = ms.raw_max_bytes()
        assert limit == 8388608
        _write(ctx.profile_home / "SOUL.md", b"a" * limit)
        res = ms.read_anchored_source(ctx.profile_home, ("SOUL.md",), limit)
        assert res.status == 200 and len(res.data) == limit
        _write(ctx.profile_home / "SOUL.md", b"a" * (limit + 1))
        res = ms.read_anchored_source(ctx.profile_home, ("SOUL.md",), limit)
        assert res.status == 413 and res.data is None

    def test_configured_16_mib_exact_limit(self, iso_state, monkeypatch):
        ctx = _ctx(iso_state)
        monkeypatch.setenv("HERMES_WEBUI_MEMORY_RAW_MAX_BYTES", "16777216")
        limit = ms.raw_max_bytes()
        _write(ctx.profile_home / "SOUL.md", b"a" * limit)
        res = ms.read_anchored_source(ctx.profile_home, ("SOUL.md",), limit)
        assert res.status == 200 and len(res.data) == limit


class TestSemaphore:
    def test_four_slots_and_fifth_busy(self, iso_state, monkeypatch):
        ctx = _ctx(iso_state)
        _write(ctx.profile_home / "SOUL.md", b"x")
        release = threading.Event()
        started = threading.Event()
        entered = {"n": 0}
        lock = threading.Lock()
        results = []
        results_lock = threading.Lock()

        def blocking_read(anchor, components, limit):
            with lock:
                entered["n"] += 1
                if entered["n"] == 4:
                    started.set()
            release.wait(timeout=10)
            return ms.ReadOutcome(status=200, data=b"x", error=None)

        monkeypatch.setattr(ms, "read_anchored_source", blocking_read)

        def worker():
            outcome = ms.read_memory_source(ctx, "soul")
            with results_lock:
                results.append(outcome.status)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        assert started.wait(timeout=10), "four readers must hold their slots"
        # All four slots are held; a fifth request fails busy without opening a source.
        busy = ms.read_memory_source(ctx, "soul")
        assert busy.status == 503 and busy.error == "raw_read_busy" and busy.retry_after == "1"
        release.set()
        for t in threads:
            t.join(timeout=10)
        assert sorted(results) == [200, 200, 200, 200]
        # Slots released after success: a fresh read completes immediately.
        assert ms.read_memory_source(ctx, "soul").status == 200

    def test_slots_release_after_success_and_error(self, iso_state):
        ctx = _ctx(iso_state)
        _write(ctx.profile_home / "SOUL.md", b"x")
        assert ms.read_memory_source(ctx, "soul").status == 200
        assert ms.read_memory_source(ctx, "soul").status == 200
        assert ms.read_memory_source(ctx, "memory").status == 404
        assert ms.read_memory_source(ctx, "memory").status == 404

    def test_invalid_limit_is_unavailable_before_slot_work(self, iso_state, monkeypatch):
        ctx = _ctx(iso_state)
        monkeypatch.setenv("HERMES_WEBUI_MEMORY_RAW_MAX_BYTES", "bogus")
        outcome = ms.read_memory_source(ctx, "soul")
        assert outcome.status == 503 and outcome.error == "raw_unavailable"


# ── Orchestration (module-level read) ───────────────────────────────────────


class TestReadMemorySource:
    def test_full_200_envelope(self, iso_state):
        ctx = _ctx(iso_state)
        raw = b"# Note\nline\n"
        _write(ctx.profile_home / "memories" / "MEMORY.md", raw)
        outcome = ms.read_memory_source(ctx, "memory")
        assert outcome.status == 200
        assert outcome.envelope["source"] == "memory"
        assert outcome.envelope["name"] == "MEMORY.md"
        assert outcome.envelope["data"] == base64.b64encode(raw).decode("ascii")
        assert outcome.body == _canonical_dumps(outcome.envelope)
        assert outcome.etag == ms.representation_etag(outcome.body)

    def test_forbidden_gate(self, iso_state):
        ctx = _ctx(iso_state)
        _write_config(ctx, {"memory": {"memory_enabled": False}})
        _write(ctx.profile_home / "memories" / "MEMORY.md", b"x")
        outcome = ms.read_memory_source(ctx, "memory")
        assert outcome.status == 403 and outcome.error == "forbidden"

    def test_not_found(self, iso_state):
        ctx = _ctx(iso_state)
        outcome = ms.read_memory_source(ctx, "memory")
        assert outcome.status == 404 and outcome.error == "not_found"

    def test_source_too_large(self, iso_state):
        ctx = _ctx(iso_state)
        _write(ctx.profile_home / "SOUL.md", b"a" * 1025)
        outcome = ms.read_memory_source(ctx, "soul", limit=1024)
        assert outcome.status == 413 and outcome.error == "source_too_large"
        assert outcome.envelope is None and outcome.body is None

    def test_invalid_selector(self, iso_state):
        outcome = ms.read_memory_source(_ctx(iso_state), "notes")
        assert outcome.status == 400 and outcome.error == "invalid_request"

    def test_project_context_end_to_end(self, iso_state, monkeypatch):
        ctx = _ctx(iso_state)
        ws = iso_state.root / "proj"
        ws.mkdir(parents=True)
        monkeypatch.setattr(ms, "_home_dir", lambda: iso_state.root / "home")
        _save_workspace(iso_state, ctx, ws)
        _write_config(ctx, {"workspace": str(ws)})
        _write(ws / ".hermes.md", b"# Project\n")
        outcome = ms.read_memory_source(ctx, "project_context")
        assert outcome.status == 200
        assert outcome.envelope["name"] == ".hermes.md"
        assert outcome.envelope["source"] == "project_context"
        assert base64.b64decode(outcome.envelope["data"]) == b"# Project\n"


# ── No-mutation boundary (§5) ───────────────────────────────────────────────


class TestNoMutationSuite:
    def _patch_every_mutating_helper(self, monkeypatch):
        import api.profiles as profiles_mod

        for name in _MUTATING_AUTH_HELPERS:
            if hasattr(auth, name):
                monkeypatch.setattr(auth, name, _boom)
        for name in _MUTATING_PROFILE_HELPERS:
            if hasattr(profiles_mod, name):
                monkeypatch.setattr(profiles_mod, name, _boom)
        for name in _MUTATING_CONFIG_HELPERS:
            if hasattr(config, name):
                monkeypatch.setattr(config, name, _boom)
        for name in _MUTATING_WORKSPACE_HELPERS:
            if hasattr(workspace, name):
                monkeypatch.setattr(workspace, name, _boom)
        for cls_name in ("Session",):
            cls = getattr(models, cls_name, None)
            if cls is not None:
                for meth in ("load", "load_metadata_only"):
                    if hasattr(cls, meth):
                        monkeypatch.setattr(cls, meth, _boom)
        if hasattr(models, "get_session"):
            monkeypatch.setattr(models, "get_session", _boom)

    def test_all_resolvers_run_with_every_mutating_helper_raising(
        self, iso_state, monkeypatch
    ):
        self._patch_every_mutating_helper(monkeypatch)
        ctx = _ctx(iso_state)
        ws = iso_state.root / "proj"
        ws.mkdir(parents=True)
        _save_workspace(iso_state, ctx, ws)
        _write_config(ctx, {"workspace": str(ws)})
        _write(ws / ".hermes.md", b"# P\n")
        _write(ctx.profile_home / "memories" / "MEMORY.md", b"# M\n")
        _write(ctx.profile_home / "SOUL.md", b"# S\n")
        _write(iso_state.state / "sessions" / "sess-1.json",
               json.dumps({"workspace": str(ws), "profile": "alice"}))

        assert ms.read_only_profile_config_snapshot(ctx)["workspace"] == str(ws)
        assert ms.read_only_profile_default_workspace(ctx) == ws
        assert ms.read_only_session_metadata(ctx, "sess-1")["workspace"] == str(ws)
        assert ms.read_only_resolve_trusted_workspace(ctx, ws) == ws
        assert ms.resolve_fixed_source(ctx, "project_context", session_id="sess-1").ok
        assert ms.read_memory_source(ctx, "memory").status == 200
        assert ms.read_memory_source(ctx, "soul").status == 200
        assert ms.read_memory_source(ctx, "project_context", session_id="sess-1").status == 200

    def test_request_profile_tls_slot_never_touched(self, iso_state, monkeypatch):
        import api.profiles as profiles_mod

        monkeypatch.setattr(profiles_mod, "set_request_profile", _boom)
        monkeypatch.setattr(profiles_mod, "clear_request_profile", _boom)
        monkeypatch.setattr(profiles_mod, "get_active_profile_name", _boom)
        ctx = _ctx(iso_state)
        _write(ctx.profile_home / "SOUL.md", b"x")
        tls = profiles_mod._tls
        before = getattr(tls, "profile", None)
        ms.read_memory_source(ctx, "soul")
        assert getattr(tls, "profile", None) is before

    def test_no_files_created_or_written_by_any_resolver(self, iso_state, monkeypatch):
        ctx = _ctx(iso_state)
        root = iso_state.root
        before = _tree_snapshot(root)
        ms.read_only_profile_config_snapshot(ctx)
        ms.read_only_profile_default_workspace(ctx)
        ms.read_only_session_metadata(ctx, "nope")
        ms.read_only_resolve_trusted_workspace(ctx, iso_state.root / "missing")
        ms.resolve_fixed_source(ctx, "memory")
        ms.read_memory_source(ctx, "soul")
        assert _tree_snapshot(root) == before
        assert not (iso_state.state / "sessions").exists()
        assert not (ctx.profile_home / "webui_state").exists()

    def test_no_mkdir_on_read(self, iso_state, monkeypatch):
        ctx = _ctx(iso_state)
        real_mkdir = Path.mkdir

        def boom_mkdir(*a, **k):
            raise AssertionError("mkdir must never be called by the raw module")

        monkeypatch.setattr(Path, "mkdir", boom_mkdir)
        # All reads must succeed without creating any directory.
        assert ms.read_only_profile_config_snapshot(ctx) == {}
        assert ms.read_only_profile_default_workspace(ctx) is None
        assert ms.read_only_session_metadata(ctx, "nope") is None
        assert ms.resolve_fixed_source(ctx, "memory").ok
        monkeypatch.setattr(Path, "mkdir", real_mkdir)


# ── Context threading (§5) ──────────────────────────────────────────────────


class TestContextThreading:
    def test_resolvers_require_the_ctx_and_never_consult_active_profile(self, iso_state, monkeypatch):
        import api.profiles as profiles_mod

        monkeypatch.setattr(profiles_mod, "get_active_profile_name", _boom)
        monkeypatch.setattr(profiles_mod, "set_request_profile", _boom)
        monkeypatch.setattr(profiles_mod, "clear_request_profile", _boom)
        ctx = _ctx(iso_state)
        _write(ctx.profile_home / "SOUL.md", b"x")
        assert ms.read_memory_source(ctx, "soul").status == 200

    def test_context_is_never_stored_in_module_globals(self):
        # After a full read there must be no module-global/thread-local ctx storage.
        assert not any(
            name.startswith("_CTX") or "context" in name.lower()
            for name in vars(ms)
            if isinstance(getattr(ms, name), auth.AuthorizedRawProfileContext)
        )
        assert not hasattr(ms, "_ctx") and not hasattr(ms, "_CONTEXT")
