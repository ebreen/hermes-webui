"""PR 0 — detached raw-memory reader seams (hermex #58, §5/§7/§8).

Tests the pure, detached, no-mutation seams introduced in PR 0 only:

- ``read_only_auth_enabled()`` — the fail-closed tri-state deployment union (§7):
  ``auth_enabled`` / ``auth_disabled`` / ``auth_state_unavailable``, with direct
  profile-home enumeration, precedence password-env > password-hash > passkey >
  OIDC > trusted-header, and no key generation, no discovery/alias caches, no
  directory creation.
- ``read_only_incoming_cookie_session_info()`` — direct no-follow
  ``STATE_DIR/.signing_key`` and ``STATE_DIR/.sessions.json`` reads (§8); returns
  a detached bound-session info record or ``None``; never mints, touches,
  prunes, persists, refreshes, or revokes a session.
- ``read_only_verify_profile_cookie()`` — the pure profile-cookie verification
  seam (§8): same token/HMAC input as ``sign_profile_cookie_value``, direct key
  read, detached comparison result only.
- ``AuthorizedRawProfileContext`` (§5) — the single immutable per-request
  context definition.
- The no-mutation suite (§5): every named mutating helper monkeypatched to
  raise; the request-profile TLS slot never touched.

No route, no dispatch, no capability, no fixtures/docs for the route: those are
PR 1 / PR 2. The route is not reachable from these tests.
"""
import dataclasses
import hashlib
import hmac
import itertools
import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import api.auth as auth
import api.profiles as profiles

WINDOWS = sys.platform == "win32"
requires_symlink = pytest.mark.skipif(
    WINDOWS,
    reason="symlink creation needs privileges on Windows",
)

_AUTH_ENV_VARS = (
    "HERMES_WEBUI_PASSWORD",
    "HERMES_WEBUI_PASSKEY",
    "HERMES_WEBUI_OIDC_ISSUER",
    "HERMES_WEBUI_OIDC_CLIENT_ID",
    "HERMES_WEBUI_OIDC_ALLOW_CLAIM",
    "HERMES_WEBUI_OIDC_ALLOW_VALUES",
    "HERMES_WEBUI_TRUSTED_AUTH_HEADER",
)


def _boom(*_args, **_kwargs):
    raise AssertionError("mutating/forbidden helper must never be called")


def _write(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, bytes):
        path.write_bytes(data)
    else:
        path.write_text(data, encoding="utf-8")


@pytest.fixture()
def iso_state(tmp_path, monkeypatch):
    """Isolated STATE_DIR and Hermes base home for one test.

    The seams resolve paths at call time from ``api.auth.STATE_DIR`` and
    ``api.profiles._DEFAULT_HERMES_HOME``, so per-test monkeypatching is
    sufficient; nothing here touches the real ~/.hermes tree.
    """
    state = tmp_path / "state"
    base = tmp_path / "base"
    monkeypatch.setattr(auth, "STATE_DIR", state)
    monkeypatch.setattr(profiles, "_DEFAULT_HERMES_HOME", base)
    monkeypatch.setattr(auth, "_PBKDF2_KEY_CACHE", None)
    monkeypatch.setattr(auth, "_SIGNING_KEY_CACHE", None)
    monkeypatch.setattr(auth, "_AUTH_HASH_CACHE", None)
    monkeypatch.setattr(auth, "_AUTH_HASH_COMPUTED", False)
    return SimpleNamespace(state=state, base=base)


@pytest.fixture()
def clean_auth_env(monkeypatch):
    """Strip every auth-relevant env var so tests start from a clean slate."""
    for name in _AUTH_ENV_VARS:
        monkeypatch.delenv(name, raising=False)


def _tree_snapshot(root: Path) -> dict:
    """Deterministic snapshot of relative path -> bytes for a directory tree."""
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


class TestAuthorizedRawProfileContext:
    """§5 — the single immutable AuthorizedRawProfileContext value object."""

    def test_carries_only_the_allowed_fields(self):
        names = [f.name for f in dataclasses.fields(auth.AuthorizedRawProfileContext)]
        assert names == [
            "bound_profile",
            "profile_home",
            "auth_session_id",
            "session_record_view",
        ]

    def test_is_frozen(self):
        ctx = auth.AuthorizedRawProfileContext(
            bound_profile="alice",
            profile_home=Path("/tmp/alice"),
            auth_session_id="tok-1",
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            ctx.bound_profile = "bob"  # type: ignore[misc]
        with pytest.raises(dataclasses.FrozenInstanceError):
            ctx.profile_home = Path("/tmp/bob")  # type: ignore[misc]
        with pytest.raises(dataclasses.FrozenInstanceError):
            ctx.auth_session_id = "tok-2"  # type: ignore[misc]

    def test_profile_home_is_normalized_to_an_absolute_resolved_path(self):
        ctx = auth.AuthorizedRawProfileContext(
            bound_profile="alice",
            profile_home=Path("/tmp") / ".." / "tmp" / "alice",
            auth_session_id="tok-1",
        )
        assert ctx.profile_home.is_absolute()
        assert ctx.profile_home == (Path("/tmp/alice").resolve())

    def test_may_carry_a_read_only_view_of_the_validated_session_record(self):
        view = {
            "token": "tok-1",
            "expiry": 1234.0,
            "bound_profile": "alice",
            "auth_type": "password",
            "username": None,
        }
        ctx = auth.AuthorizedRawProfileContext(
            bound_profile="alice",
            profile_home=Path("/tmp/alice"),
            auth_session_id="tok-1",
            session_record_view=view,
        )
        assert ctx.session_record_view["bound_profile"] == "alice"
        assert ctx.session_record_view["expiry"] == 1234.0

    def test_rejects_empty_bound_profile(self):
        with pytest.raises(ValueError):
            auth.AuthorizedRawProfileContext(
                bound_profile="   ",
                profile_home=Path("/tmp/alice"),
                auth_session_id="tok-1",
            )

    def test_rejects_empty_auth_session_id(self):
        with pytest.raises(ValueError):
            auth.AuthorizedRawProfileContext(
                bound_profile="alice",
                profile_home=Path("/tmp/alice"),
                auth_session_id="",
            )

    def test_rejects_non_path_profile_home(self):
        with pytest.raises(ValueError):
            auth.AuthorizedRawProfileContext(
                bound_profile="alice",
                profile_home="/tmp/alice",  # type: ignore[arg-type]
                auth_session_id="tok-1",
            )


class TestReadOnlyAuthEnabledUnion:
    """§7 — fail-closed tri-state deployment union."""

    def test_all_union_members_readable_and_disabled_returns_auth_disabled(
        self, iso_state, clean_auth_env
    ):
        assert auth.read_only_auth_enabled() == auth.AUTH_DISABLED

    def test_empty_config_yaml_is_readable_and_disabled(self, iso_state, clean_auth_env):
        _write(iso_state.base / "config.yaml", "")
        assert auth.read_only_auth_enabled() == auth.AUTH_DISABLED

    def test_missing_named_profile_config_is_readable_and_disabled(
        self, iso_state, clean_auth_env
    ):
        (iso_state.base / "profiles" / "alice").mkdir(parents=True)
        assert auth.read_only_auth_enabled() == auth.AUTH_DISABLED

    def test_password_env_enabled(self, iso_state, clean_auth_env, monkeypatch):
        monkeypatch.setenv("HERMES_WEBUI_PASSWORD", "s3cret")
        assert auth.read_only_auth_enabled() == auth.AUTH_ENABLED

    def test_configured_password_hash_in_global_settings_enabled(
        self, iso_state, clean_auth_env
    ):
        _write(
            iso_state.state / "settings.json",
            json.dumps({"password_hash": "a" * 64}),
        )
        assert auth.read_only_auth_enabled() == auth.AUTH_ENABLED

    def test_empty_password_hash_is_readable_and_disabled(
        self, iso_state, clean_auth_env
    ):
        _write(iso_state.state / "settings.json", json.dumps({"password_hash": ""}))
        assert auth.read_only_auth_enabled() == auth.AUTH_DISABLED

    def test_passkey_enabled_in_root_profile_config(self, iso_state, clean_auth_env):
        _write(iso_state.base / "config.yaml", "webui_passkey_enabled: true\n")
        _write(
            iso_state.state / "passkeys.json",
            json.dumps([{"id": "cred-1", "label": "key"}], indent=2),
        )
        assert auth.read_only_auth_enabled() == auth.AUTH_ENABLED

    def test_passkey_env_flag_with_credentials_enabled(
        self, iso_state, clean_auth_env, monkeypatch
    ):
        monkeypatch.setenv("HERMES_WEBUI_PASSKEY", "1")
        _write(
            iso_state.state / "passkeys.json",
            json.dumps([{"id": "cred-1"}], indent=2),
        )
        assert auth.read_only_auth_enabled() == auth.AUTH_ENABLED

    def test_passkey_flag_without_credentials_is_readable_disabled(
        self, iso_state, clean_auth_env
    ):
        _write(iso_state.base / "config.yaml", "webui_passkey_enabled: true\n")
        assert auth.read_only_auth_enabled() == auth.AUTH_DISABLED

    def test_passkey_credentials_without_flag_are_readable_disabled(
        self, iso_state, clean_auth_env
    ):
        _write(
            iso_state.state / "passkeys.json",
            json.dumps([{"id": "cred-1"}], indent=2),
        )
        assert auth.read_only_auth_enabled() == auth.AUTH_DISABLED

    def test_oidc_enabled_in_root_profile_config(self, iso_state, clean_auth_env):
        _write(
            iso_state.base / "config.yaml",
            "webui_oidc:\n"
            "  issuer: https://idp.example\n"
            "  client_id: webui\n"
            "  allow_claim: groups\n"
            '  allow_values: ["eng"]\n',
        )
        assert auth.read_only_auth_enabled() == auth.AUTH_ENABLED

    def test_oidc_enabled_via_env_vars(self, iso_state, clean_auth_env, monkeypatch):
        monkeypatch.setenv("HERMES_WEBUI_OIDC_ISSUER", "https://idp.example")
        monkeypatch.setenv("HERMES_WEBUI_OIDC_CLIENT_ID", "webui")
        monkeypatch.setenv("HERMES_WEBUI_OIDC_ALLOW_CLAIM", "groups")
        monkeypatch.setenv("HERMES_WEBUI_OIDC_ALLOW_VALUES", "eng")
        assert auth.read_only_auth_enabled() == auth.AUTH_ENABLED

    def test_trusted_header_alone_enables_auth(self, iso_state, clean_auth_env, monkeypatch):
        monkeypatch.setenv("HERMES_WEBUI_TRUSTED_AUTH_HEADER", "X-Remote-User")
        assert auth.read_only_auth_enabled() == auth.AUTH_ENABLED

    def test_auth_enabled_only_in_a_non_current_profile(
        self, iso_state, clean_auth_env
    ):
        """§7 required test: a *named* profile's config alone enables the union.

        The union is deployment-wide; the requested/current profile's own config
        is irrelevant — auth enabled anywhere in the union means auth_enabled.
        """
        _write(
            iso_state.base / "profiles" / "alice" / "config.yaml",
            "webui_oidc:\n"
            "  issuer: https://idp.example\n"
            "  client_id: webui\n"
            "  allow_claim: groups\n"
            '  allow_values: ["eng"]\n',
        )
        assert auth.read_only_auth_enabled() == auth.AUTH_ENABLED

    def test_auth_enabled_only_in_a_named_profile_via_passkeys(
        self, iso_state, clean_auth_env
    ):
        _write(iso_state.base / "profiles" / "alice" / "config.yaml", "webui_passkey_enabled: true\n")
        _write(
            iso_state.state / "passkeys.json",
            json.dumps([{"id": "cred-1"}], indent=2),
        )
        assert auth.read_only_auth_enabled() == auth.AUTH_ENABLED

    def test_every_readable_subset_of_the_union_is_enabled(
        self, iso_state, clean_auth_env, monkeypatch
    ):
        """Precedence union: password env > password hash > passkey > OIDC >
        trusted-header. All 31 non-empty readable combinations are auth_enabled.

        Each posture is applied alone or in combination; the union is the OR of
        all readable states, so any non-empty readable subset must be enabled.
        """

        def apply_posture(name: str) -> None:
            if name == "password_env":
                monkeypatch.setenv("HERMES_WEBUI_PASSWORD", "pw")
            elif name == "password_hash":
                _write(
                    iso_state.state / "settings.json",
                    json.dumps({"password_hash": "b" * 64}),
                )
            elif name == "passkey":
                _write(iso_state.base / "config.yaml", "webui_passkey_enabled: true\n")
                _write(
                    iso_state.state / "passkeys.json",
                    json.dumps([{"id": "cred-1"}], indent=2),
                )
            elif name == "oidc":
                _write(
                    iso_state.base / "config.yaml",
                    "webui_oidc:\n"
                    "  issuer: https://idp.example\n"
                    "  client_id: webui\n"
                    "  allow_claim: groups\n"
                    '  allow_values: ["eng"]\n',
                )
            elif name == "trusted_header":
                monkeypatch.setenv("HERMES_WEBUI_TRUSTED_AUTH_HEADER", "X-Remote-User")
            else:  # pragma: no cover
                raise AssertionError(name)

        postures = ["password_env", "password_hash", "passkey", "oidc", "trusted_header"]
        for size in range(1, len(postures) + 1):
            for combo in itertools.combinations(postures, size):
                for name in combo:
                    apply_posture(name)
                assert auth.read_only_auth_enabled() == auth.AUTH_ENABLED, (
                    f"union must be enabled for readable subset {combo}"
                )
                # Reset between combinations (keep env stripped for env postures).
                for name in combo:
                    if name in ("password_env", "trusted_header"):
                        monkeypatch.delenv(
                            "HERMES_WEBUI_PASSWORD" if name == "password_env"
                            else "HERMES_WEBUI_TRUSTED_AUTH_HEADER",
                            raising=False,
                        )

    # ── Fail-closed: unreadable / malformed / partially configured ──────────

    @requires_symlink
    def test_unreadable_global_settings_is_unavailable(self, iso_state, clean_auth_env):
        _write(iso_state.state / "settings.json", json.dumps({"password_hash": "a" * 64}))
        (iso_state.state / "settings.json").unlink()
        (iso_state.state / "settings.json").symlink_to("/etc/hostname")
        assert auth.read_only_auth_enabled() == auth.AUTH_STATE_UNAVAILABLE

    def test_malformed_global_settings_is_unavailable(self, iso_state, clean_auth_env):
        _write(iso_state.state / "settings.json", "{ not json")
        assert auth.read_only_auth_enabled() == auth.AUTH_STATE_UNAVAILABLE

    def test_non_dict_global_settings_is_unavailable(self, iso_state, clean_auth_env):
        _write(iso_state.state / "settings.json", "[1, 2, 3]")
        assert auth.read_only_auth_enabled() == auth.AUTH_STATE_UNAVAILABLE

    def test_non_string_password_hash_is_unavailable(self, iso_state, clean_auth_env):
        _write(iso_state.state / "settings.json", json.dumps({"password_hash": 123}))
        assert auth.read_only_auth_enabled() == auth.AUTH_STATE_UNAVAILABLE

    @requires_symlink
    def test_unreadable_root_profile_config_is_unavailable(self, iso_state, clean_auth_env):
        (iso_state.base).mkdir(parents=True)
        (iso_state.base / "config.yaml").symlink_to("/etc/hostname")
        assert auth.read_only_auth_enabled() == auth.AUTH_STATE_UNAVAILABLE

    def test_malformed_root_profile_config_is_unavailable(self, iso_state, clean_auth_env):
        _write(iso_state.base / "config.yaml", "{{{{ not yaml")
        assert auth.read_only_auth_enabled() == auth.AUTH_STATE_UNAVAILABLE

    def test_non_dict_profile_config_is_unavailable(self, iso_state, clean_auth_env):
        _write(iso_state.base / "config.yaml", "- one\n- two\n")
        assert auth.read_only_auth_enabled() == auth.AUTH_STATE_UNAVAILABLE

    @requires_symlink
    def test_unreadable_named_profile_config_is_unavailable(
        self, iso_state, clean_auth_env
    ):
        (iso_state.base / "profiles" / "alice").mkdir(parents=True)
        (iso_state.base / "profiles" / "alice" / "config.yaml").symlink_to(
            "/etc/hostname"
        )
        assert auth.read_only_auth_enabled() == auth.AUTH_STATE_UNAVAILABLE

    def test_malformed_named_profile_config_is_unavailable(
        self, iso_state, clean_auth_env
    ):
        _write(iso_state.base / "profiles" / "alice" / "config.yaml", "{{{{ not yaml")
        assert auth.read_only_auth_enabled() == auth.AUTH_STATE_UNAVAILABLE

    def test_malformed_passkey_flag_value_is_unavailable(self, iso_state, clean_auth_env):
        _write(iso_state.base / "config.yaml", "webui_passkey_enabled: banana\n")
        assert auth.read_only_auth_enabled() == auth.AUTH_STATE_UNAVAILABLE

    def test_non_bool_passkey_flag_value_is_unavailable(self, iso_state, clean_auth_env):
        _write(iso_state.base / "config.yaml", "webui_passkey_enabled: 42\n")
        assert auth.read_only_auth_enabled() == auth.AUTH_STATE_UNAVAILABLE

    def test_malformed_passkey_env_flag_is_unavailable(
        self, iso_state, clean_auth_env, monkeypatch
    ):
        monkeypatch.setenv("HERMES_WEBUI_PASSKEY", "banana")
        assert auth.read_only_auth_enabled() == auth.AUTH_STATE_UNAVAILABLE

    def test_partially_configured_oidc_is_unavailable(self, iso_state, clean_auth_env):
        _write(
            iso_state.base / "config.yaml",
            "webui_oidc:\n  issuer: https://idp.example\n",
        )
        assert auth.read_only_auth_enabled() == auth.AUTH_STATE_UNAVAILABLE

    def test_partially_configured_oidc_env_is_unavailable(
        self, iso_state, clean_auth_env, monkeypatch
    ):
        monkeypatch.setenv("HERMES_WEBUI_OIDC_ISSUER", "https://idp.example")
        assert auth.read_only_auth_enabled() == auth.AUTH_STATE_UNAVAILABLE

    def test_malformed_oidc_value_is_unavailable(self, iso_state, clean_auth_env):
        _write(iso_state.base / "config.yaml", "webui_oidc: true\n")
        assert auth.read_only_auth_enabled() == auth.AUTH_STATE_UNAVAILABLE

    @requires_symlink
    def test_unreadable_passkey_credentials_are_unavailable(
        self, iso_state, clean_auth_env
    ):
        _write(iso_state.base / "config.yaml", "webui_passkey_enabled: true\n")
        _write(iso_state.state / "passkeys.json", json.dumps([{"id": "cred-1"}]))
        (iso_state.state / "passkeys.json").unlink()
        (iso_state.state / "passkeys.json").symlink_to("/etc/hostname")
        assert auth.read_only_auth_enabled() == auth.AUTH_STATE_UNAVAILABLE

    def test_malformed_passkey_credentials_are_unavailable(
        self, iso_state, clean_auth_env
    ):
        _write(iso_state.base / "config.yaml", "webui_passkey_enabled: true\n")
        _write(iso_state.state / "passkeys.json", "{ not json")
        assert auth.read_only_auth_enabled() == auth.AUTH_STATE_UNAVAILABLE

    def test_non_list_passkey_credentials_are_unavailable(
        self, iso_state, clean_auth_env
    ):
        _write(iso_state.base / "config.yaml", "webui_passkey_enabled: true\n")
        _write(iso_state.state / "passkeys.json", json.dumps({"id": "cred-1"}))
        assert auth.read_only_auth_enabled() == auth.AUTH_STATE_UNAVAILABLE

    def test_union_fails_closed_when_enabled_and_unreadable_coexist(
        self, iso_state, clean_auth_env, monkeypatch
    ):
        """Unknown state is never treated as disabled — and never silently
        ignored: a malformed profile config wins over an enabled password env."""
        monkeypatch.setenv("HERMES_WEBUI_PASSWORD", "pw")
        _write(iso_state.base / "profiles" / "alice" / "config.yaml", "{{{{ not yaml")
        assert auth.read_only_auth_enabled() == auth.AUTH_STATE_UNAVAILABLE

    # ── No key generation / no caches / no creation ─────────────────────────

    def test_no_key_generation_on_any_path(self, iso_state, clean_auth_env, monkeypatch):
        monkeypatch.setenv("HERMES_WEBUI_PASSWORD", "pw")
        assert auth.read_only_auth_enabled() == auth.AUTH_ENABLED
        assert not (iso_state.state / ".signing_key").exists()
        assert not (iso_state.state / ".pbkdf2_key").exists()

    def test_configured_password_with_missing_key_file_is_still_enabled(
        self, iso_state, clean_auth_env, monkeypatch
    ):
        monkeypatch.setenv("HERMES_WEBUI_PASSWORD", "pw")
        assert auth.read_only_auth_enabled() == auth.AUTH_ENABLED
        assert not (iso_state.state / ".signing_key").exists()

    def test_direct_enumeration_no_discovery_or_alias_caches(
        self, iso_state, clean_auth_env, monkeypatch
    ):
        """Direct profile-home enumeration: no list_profiles_api(), no
        _is_root_profile(), no _profiles_match(), no cache invalidation."""
        monkeypatch.setattr(profiles, "list_profiles_api", _boom)
        monkeypatch.setattr(profiles, "_is_root_profile", _boom)
        monkeypatch.setattr(profiles, "_profiles_match", _boom)
        monkeypatch.setattr(profiles, "_invalidate_root_profile_cache", _boom)
        monkeypatch.setattr(profiles, "get_active_profile_name", _boom)
        assert auth.read_only_auth_enabled() == auth.AUTH_DISABLED

    def test_direct_enumeration_never_creates_directories(
        self, iso_state, clean_auth_env
    ):
        assert not iso_state.state.exists()
        assert not iso_state.base.exists()
        assert auth.read_only_auth_enabled() == auth.AUTH_DISABLED
        assert not iso_state.state.exists()
        assert not iso_state.base.exists()
        assert not (iso_state.base / "profiles").exists()

    def test_direct_enumeration_sees_named_profile_homes(
        self, iso_state, clean_auth_env
    ):
        _write(
            iso_state.base / "profiles" / "bob" / "config.yaml",
            "webui_oidc:\n"
            "  issuer: https://idp.example\n"
            "  client_id: webui\n"
            "  allow_claim: groups\n"
            '  allow_values: ["eng"]\n',
        )
        assert auth.read_only_auth_enabled() == auth.AUTH_ENABLED

    def test_union_reads_do_not_write_any_state(self, iso_state, clean_auth_env, monkeypatch):
        monkeypatch.setenv("HERMES_WEBUI_PASSWORD", "pw")
        _write(
            iso_state.base / "profiles" / "alice" / "config.yaml",
            "webui_passkey_enabled: true\n",
        )
        _write(iso_state.state / "passkeys.json", json.dumps([{"id": "cred-1"}]))
        before = _tree_snapshot(tmp_root := iso_state.state.parent)
        assert auth.read_only_auth_enabled() == auth.AUTH_ENABLED
        assert _tree_snapshot(tmp_root) == before

    def test_union_never_consults_the_active_profile(
        self, iso_state, clean_auth_env, monkeypatch
    ):
        monkeypatch.setattr(profiles, "get_active_profile_name", _boom)
        assert auth.read_only_auth_enabled() == auth.AUTH_DISABLED


def _write_session_store(state: Path, records: dict) -> None:
    _write(state / ".sessions.json", json.dumps(records, indent=2))


def _signed_cookie(token: str, key: bytes, *, truncate: bool = False) -> str:
    sig = hmac.new(key, token.encode(), hashlib.sha256).hexdigest()
    if truncate:
        sig = sig[:32]
    return f"{token}.{sig}"


class TestReadOnlyIncomingCookieSessionInfo:
    """§8 — direct signing-key and STATE_DIR/.sessions.json reads; no mutation."""

    def _setup(self, iso_state, monkeypatch, key: bytes = b"k" * 32):
        monkeypatch.setattr(profiles, "set_request_profile", _boom)
        monkeypatch.setattr(profiles, "clear_request_profile", _boom)
        _write(iso_state.state / ".signing_key", key)

    def test_valid_cookie_returns_detached_bound_session_info(
        self, iso_state, clean_auth_env, monkeypatch
    ):
        self._setup(iso_state, monkeypatch)
        expiry = time.time() + 3600
        _write_session_store(
            iso_state.state,
            {
                "tok-1": {
                    "expiry": expiry,
                    "auth_type": "password",
                    "username": "u",
                    "bound_profile": "alice",
                }
            },
        )
        info = auth.read_only_incoming_cookie_session_info(
            _signed_cookie("tok-1", b"k" * 32)
        )
        assert info == {
            "token": "tok-1",
            "expiry": expiry,
            "auth_type": "password",
            "username": "u",
            "bound_profile": "alice",
        }

    def test_legacy_32_char_signature_form_is_accepted(
        self, iso_state, clean_auth_env, monkeypatch
    ):
        self._setup(iso_state, monkeypatch)
        _write_session_store(iso_state.state, {"tok-1": time.time() + 3600})
        info = auth.read_only_incoming_cookie_session_info(
            _signed_cookie("tok-1", b"k" * 32, truncate=True)
        )
        assert info is not None
        assert info["token"] == "tok-1"

    def test_float_session_record_returns_info_with_none_bindings(
        self, iso_state, clean_auth_env, monkeypatch
    ):
        self._setup(iso_state, monkeypatch)
        expiry = time.time() + 3600
        _write_session_store(iso_state.state, {"tok-1": expiry})
        info = auth.read_only_incoming_cookie_session_info(
            _signed_cookie("tok-1", b"k" * 32)
        )
        assert info == {
            "token": "tok-1",
            "expiry": expiry,
            "auth_type": None,
            "username": None,
            "bound_profile": None,
        }

    def test_legacy_profile_key_is_mapped_to_bound_profile(
        self, iso_state, clean_auth_env, monkeypatch
    ):
        self._setup(iso_state, monkeypatch)
        _write_session_store(
            iso_state.state,
            {"tok-1": {"expiry": time.time() + 3600, "profile": "bob"}},
        )
        info = auth.read_only_incoming_cookie_session_info(
            _signed_cookie("tok-1", b"k" * 32)
        )
        assert info["bound_profile"] == "bob"

    def test_info_never_contains_cookie_value_or_key_material(
        self, iso_state, clean_auth_env, monkeypatch
    ):
        self._setup(iso_state, monkeypatch)
        _write_session_store(
            iso_state.state,
            {"tok-1": {"expiry": time.time() + 3600, "bound_profile": "alice"}},
        )
        info = auth.read_only_incoming_cookie_session_info(
            _signed_cookie("tok-1", b"k" * 32)
        )
        assert set(info.keys()) == {"token", "expiry", "auth_type", "username", "bound_profile"}
        assert "k" * 32 not in str(info)
        assert info["token"] == "tok-1"  # session id only, never the signed cookie

    def test_invalid_signature_returns_none(self, iso_state, clean_auth_env, monkeypatch):
        self._setup(iso_state, monkeypatch)
        _write_session_store(iso_state.state, {"tok-1": time.time() + 3600})
        cookie = _signed_cookie("tok-1", b"k" * 32)
        tampered = cookie[:-1] + ("0" if cookie[-1] != "0" else "1")
        assert auth.read_only_incoming_cookie_session_info(tampered) is None

    def test_empty_or_malformed_cookie_returns_none(
        self, iso_state, clean_auth_env, monkeypatch
    ):
        self._setup(iso_state, monkeypatch)
        _write_session_store(iso_state.state, {"tok-1": time.time() + 3600})
        assert auth.read_only_incoming_cookie_session_info("") is None
        assert auth.read_only_incoming_cookie_session_info("no-dot") is None
        assert auth.read_only_incoming_cookie_session_info(".sigonly") is None
        assert auth.read_only_incoming_cookie_session_info("tok.") is None

    def test_unknown_token_returns_none(self, iso_state, clean_auth_env, monkeypatch):
        self._setup(iso_state, monkeypatch)
        _write_session_store(iso_state.state, {"tok-1": time.time() + 3600})
        assert (
            auth.read_only_incoming_cookie_session_info(
                _signed_cookie("tok-unknown", b"k" * 32)
            )
            is None
        )

    def test_expired_session_returns_none_without_pruning_or_persisting(
        self, iso_state, clean_auth_env, monkeypatch
    ):
        self._setup(iso_state, monkeypatch)
        store = {"tok-1": {"expiry": time.time() - 10, "bound_profile": "alice"}}
        _write_session_store(iso_state.state, store)
        original_bytes = (iso_state.state / ".sessions.json").read_bytes()
        assert (
            auth.read_only_incoming_cookie_session_info(
                _signed_cookie("tok-1", b"k" * 32)
            )
            is None
        )
        # The expired record must NOT be pruned or persisted away.
        assert (iso_state.state / ".sessions.json").read_bytes() == original_bytes

    def test_future_expiry_is_valid_past_expiry_is_not(
        self, iso_state, clean_auth_env, monkeypatch
    ):
        self._setup(iso_state, monkeypatch)
        _write_session_store(
            iso_state.state,
            {
                "future": time.time() + 3600,
                "past": time.time() - 1,
            },
        )
        assert (
            auth.read_only_incoming_cookie_session_info(_signed_cookie("future", b"k" * 32))
            is not None
        )
        assert (
            auth.read_only_incoming_cookie_session_info(_signed_cookie("past", b"k" * 32))
            is None
        )

    def test_parity_with_a_real_minted_session(
        self, iso_state, clean_auth_env, monkeypatch
    ):
        """A cookie minted by create_session() validates with identical info.

        Minting happens only in the test setup; the seam itself never mints.
        """
        monkeypatch.setattr(auth, "_SESSIONS_FILE", iso_state.state / ".sessions.json")
        monkeypatch.setattr(auth, "_sessions", {})
        cookie = auth.create_session(
            auth_type="password", username="u", bound_profile="alice"
        )
        info = auth.read_only_incoming_cookie_session_info(cookie)
        assert info is not None
        assert info["token"] == cookie.rsplit(".", 1)[0]
        assert info["auth_type"] == "password"
        assert info["username"] == "u"
        assert info["bound_profile"] == "alice"
        assert info["expiry"] > time.time()
        assert set(info.keys()) == {"token", "expiry", "auth_type", "username", "bound_profile"}

    def test_missing_signing_key_returns_none(self, iso_state, clean_auth_env, monkeypatch):
        self._setup(iso_state, monkeypatch)
        (iso_state.state / ".signing_key").unlink()
        _write_session_store(iso_state.state, {"tok-1": time.time() + 3600})
        assert (
            auth.read_only_incoming_cookie_session_info(_signed_cookie("tok-1", b"k" * 32))
            is None
        )

    def test_short_signing_key_returns_none(self, iso_state, clean_auth_env, monkeypatch):
        self._setup(iso_state, monkeypatch, key=b"short")
        _write_session_store(iso_state.state, {"tok-1": time.time() + 3600})
        assert (
            auth.read_only_incoming_cookie_session_info(_signed_cookie("tok-1", b"k" * 32))
            is None
        )

    @requires_symlink
    def test_symlinked_signing_key_fails_closed(self, iso_state, clean_auth_env, monkeypatch):
        self._setup(iso_state, monkeypatch)
        (iso_state.state / ".signing_key").unlink()
        (iso_state.state / ".signing_key").symlink_to("/etc/hostname")
        _write_session_store(iso_state.state, {"tok-1": time.time() + 3600})
        assert (
            auth.read_only_incoming_cookie_session_info(_signed_cookie("tok-1", b"k" * 32))
            is None
        )

    def test_missing_sessions_file_returns_none(self, iso_state, clean_auth_env, monkeypatch):
        self._setup(iso_state, monkeypatch)
        assert (
            auth.read_only_incoming_cookie_session_info(_signed_cookie("tok-1", b"k" * 32))
            is None
        )

    def test_malformed_sessions_file_returns_none(
        self, iso_state, clean_auth_env, monkeypatch
    ):
        self._setup(iso_state, monkeypatch)
        _write(iso_state.state / ".sessions.json", "{ not json")
        assert (
            auth.read_only_incoming_cookie_session_info(_signed_cookie("tok-1", b"k" * 32))
            is None
        )

    def test_non_dict_sessions_file_returns_none(
        self, iso_state, clean_auth_env, monkeypatch
    ):
        self._setup(iso_state, monkeypatch)
        _write(iso_state.state / ".sessions.json", "[1, 2]")
        assert (
            auth.read_only_incoming_cookie_session_info(_signed_cookie("tok-1", b"k" * 32))
            is None
        )

    @requires_symlink
    def test_symlinked_sessions_file_returns_none(self, iso_state, clean_auth_env, monkeypatch):
        self._setup(iso_state, monkeypatch)
        _write(iso_state.state / "sessions-real.json", json.dumps({"tok-1": time.time() + 3600}))
        (iso_state.state / ".sessions.json").symlink_to(
            iso_state.state / "sessions-real.json"
        )
        assert (
            auth.read_only_incoming_cookie_session_info(_signed_cookie("tok-1", b"k" * 32))
            is None
        )

    def test_valid_cookie_path_never_mutates_sessions_store(
        self, iso_state, clean_auth_env, monkeypatch
    ):
        self._setup(iso_state, monkeypatch)
        monkeypatch.setattr(auth, "_prune_expired_sessions", _boom)
        monkeypatch.setattr(auth, "_save_sessions", _boom)
        monkeypatch.setattr(auth, "_load_sessions", _boom)
        monkeypatch.setattr(auth, "create_session", _boom)
        monkeypatch.setattr(auth, "invalidate_session", _boom)
        store = {"tok-1": {"expiry": time.time() + 3600, "bound_profile": "alice"}}
        _write_session_store(iso_state.state, store)
        original_bytes = (iso_state.state / ".sessions.json").read_bytes()
        info = auth.read_only_incoming_cookie_session_info(
            _signed_cookie("tok-1", b"k" * 32)
        )
        assert info is not None
        assert (iso_state.state / ".sessions.json").read_bytes() == original_bytes
        assert not (iso_state.state / ".pbkdf2_key").exists()

    def test_invalid_cookie_path_never_mutates_sessions_store(
        self, iso_state, clean_auth_env, monkeypatch
    ):
        self._setup(iso_state, monkeypatch)
        monkeypatch.setattr(auth, "_prune_expired_sessions", _boom)
        monkeypatch.setattr(auth, "_save_sessions", _boom)
        monkeypatch.setattr(auth, "_load_sessions", _boom)
        monkeypatch.setattr(auth, "create_session", _boom)
        monkeypatch.setattr(auth, "invalidate_session", _boom)
        _write_session_store(iso_state.state, {"tok-1": time.time() + 3600})
        original_bytes = (iso_state.state / ".sessions.json").read_bytes()
        assert (
            auth.read_only_incoming_cookie_session_info("garbage.invalid")
            is None
        )
        assert (iso_state.state / ".sessions.json").read_bytes() == original_bytes


class TestReadOnlyVerifyProfileCookie:
    """§8 — pure profile-cookie verification seam (detached comparison only)."""

    def _profile_cookie(self, profile_name: str, token: str, key: bytes) -> str:
        sig = hmac.new(
            key, f"profile:{token}:{profile_name}".encode(), hashlib.sha256
        ).hexdigest()
        return f"{profile_name}.{sig}"

    def test_valid_profile_cookie_returns_profile_name(
        self, iso_state, clean_auth_env, monkeypatch
    ):
        _write(iso_state.state / ".signing_key", b"k" * 32)
        cookie = self._profile_cookie("alice", "tok-1", b"k" * 32)
        assert (
            auth.read_only_verify_profile_cookie(cookie, _signed_cookie("tok-1", b"k" * 32))
            == "alice"
        )

    def test_default_profile_name_is_allowed(
        self, iso_state, clean_auth_env, monkeypatch
    ):
        _write(iso_state.state / ".signing_key", b"k" * 32)
        cookie = self._profile_cookie("default", "tok-1", b"k" * 32)
        assert (
            auth.read_only_verify_profile_cookie(cookie, _signed_cookie("tok-1", b"k" * 32))
            == "default"
        )

    def test_tampered_signature_returns_none(self, iso_state, clean_auth_env, monkeypatch):
        _write(iso_state.state / ".signing_key", b"k" * 32)
        cookie = self._profile_cookie("alice", "tok-1", b"k" * 32)
        tampered = cookie[:-1] + ("0" if cookie[-1] != "0" else "1")
        assert (
            auth.read_only_verify_profile_cookie(tampered, _signed_cookie("tok-1", b"k" * 32))
            is None
        )

    def test_wrong_session_token_returns_none(self, iso_state, clean_auth_env, monkeypatch):
        _write(iso_state.state / ".signing_key", b"k" * 32)
        cookie = self._profile_cookie("alice", "tok-1", b"k" * 32)
        assert (
            auth.read_only_verify_profile_cookie(cookie, _signed_cookie("tok-other", b"k" * 32))
            is None
        )

    def test_empty_or_malformed_values_return_none(
        self, iso_state, clean_auth_env, monkeypatch
    ):
        _write(iso_state.state / ".signing_key", b"k" * 32)
        session = _signed_cookie("tok-1", b"k" * 32)
        assert auth.read_only_verify_profile_cookie("", session) is None
        assert auth.read_only_verify_profile_cookie("no-dot", session) is None
        assert auth.read_only_verify_profile_cookie("alice.", session) is None
        assert auth.read_only_verify_profile_cookie(".sig", session) is None
        assert auth.read_only_verify_profile_cookie("alice.sig", "") is None
        assert auth.read_only_verify_profile_cookie("alice.sig", "no-dot") is None
        assert auth.read_only_verify_profile_cookie("alice.sig", None) is None

    def test_invalid_profile_name_pattern_returns_none(
        self, iso_state, clean_auth_env, monkeypatch
    ):
        _write(iso_state.state / ".signing_key", b"k" * 32)
        cookie = self._profile_cookie("Bad Name", "tok-1", b"k" * 32)
        assert (
            auth.read_only_verify_profile_cookie(cookie, _signed_cookie("tok-1", b"k" * 32))
            is None
        )

    def test_detached_comparison_does_not_require_a_live_session_record(
        self, iso_state, clean_auth_env, monkeypatch
    ):
        """The seam verifies only the token/HMAC binding; session validity is
        established by the auth-cookie gate before this seam runs (§8 step 2)."""
        _write(iso_state.state / ".signing_key", b"k" * 32)
        cookie = self._profile_cookie("alice", "tok-1", b"k" * 32)
        # No .sessions.json at all — the detached comparison still resolves.
        assert (
            auth.read_only_verify_profile_cookie(cookie, _signed_cookie("tok-1", b"k" * 32))
            == "alice"
        )

    def test_no_mutating_helper_is_reached(self, iso_state, clean_auth_env, monkeypatch):
        _write(iso_state.state / ".signing_key", b"k" * 32)
        import api.helpers as helpers

        monkeypatch.setattr(auth, "_signing_key", _boom)
        monkeypatch.setattr(auth, "_load_key", _boom)
        monkeypatch.setattr(auth, "verify_session", _boom)
        monkeypatch.setattr(auth, "get_session_info", _boom)
        monkeypatch.setattr(auth, "verify_profile_cookie_value", _boom)
        monkeypatch.setattr(auth, "parse_cookie", _boom)
        for name in ("get_profile_cookie", "get_profile_cookie_name"):
            if hasattr(helpers, name):
                monkeypatch.setattr(helpers, name, _boom)
        monkeypatch.setattr(profiles, "set_request_profile", _boom)
        monkeypatch.setattr(profiles, "clear_request_profile", _boom)
        cookie = self._profile_cookie("alice", "tok-1", b"k" * 32)
        assert (
            auth.read_only_verify_profile_cookie(cookie, _signed_cookie("tok-1", b"k" * 32))
            == "alice"
        )

    @requires_symlink
    def test_symlinked_signing_key_fails_closed(self, iso_state, clean_auth_env, monkeypatch):
        _write(iso_state.state / "real-key", b"k" * 32)
        (iso_state.state / ".signing_key").symlink_to(iso_state.state / "real-key")
        cookie = self._profile_cookie("alice", "tok-1", b"k" * 32)
        assert (
            auth.read_only_verify_profile_cookie(cookie, _signed_cookie("tok-1", b"k" * 32))
            is None
        )


class TestNoMutationSuite:
    """§5 — every named mutating helper monkeypatched to raise; TLS slot untouched."""

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
        "_build_profile_cookie_header",
        "_clear_auth_cookie_header",
        "parse_cookie",
        "check_auth",
        "ensure_trusted_auth_session",
        "_apply_trusted_session_profile",
        "_remember_trusted_auth_session",
        "reset_trusted_auth_request_state",
        "sign_profile_cookie_value",
        "verify_profile_cookie_value",
        "_invalidate_password_hash_cache",
        "_warn_trusted_auth_once",
        "_warn_auth_persistence_failure",
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

    def _patch_every_mutating_helper(self, monkeypatch):
        import api.config as config

        for name in self._MUTATING_AUTH_HELPERS:
            if hasattr(auth, name):
                monkeypatch.setattr(auth, name, _boom)
        for name in self._MUTATING_PROFILE_HELPERS:
            if hasattr(profiles, name):
                monkeypatch.setattr(profiles, name, _boom)
        for name in self._MUTATING_CONFIG_HELPERS:
            if hasattr(config, name):
                monkeypatch.setattr(config, name, _boom)

    def test_all_seams_run_with_every_mutating_helper_raising(
        self, iso_state, clean_auth_env, monkeypatch
    ):
        self._patch_every_mutating_helper(monkeypatch)
        monkeypatch.setenv("HERMES_WEBUI_PASSWORD", "pw")
        _write(iso_state.state / ".signing_key", b"k" * 32)
        _write_session_store(
            iso_state.state,
            {"tok-1": {"expiry": time.time() + 3600, "bound_profile": "alice"}},
        )
        # The union must not call any mutating/config-cache helper.
        assert auth.read_only_auth_enabled() == auth.AUTH_ENABLED
        # The cookie seam must not call any mutating session/key helper.
        info = auth.read_only_incoming_cookie_session_info(
            _signed_cookie("tok-1", b"k" * 32)
        )
        assert info is not None and info["bound_profile"] == "alice"
        # The profile-cookie seam must not call any mutating helper.
        sig = hmac.new(
            b"k" * 32, b"profile:tok-1:alice", hashlib.sha256
        ).hexdigest()
        assert (
            auth.read_only_verify_profile_cookie(
                f"alice.{sig}", _signed_cookie("tok-1", b"k" * 32)
            )
            == "alice"
        )
        # The context is a pure value object.
        ctx = auth.AuthorizedRawProfileContext(
            bound_profile="alice",
            profile_home=iso_state.base / "profiles" / "alice",
            auth_session_id="tok-1",
        )
        assert ctx.bound_profile == "alice"

    def test_request_profile_tls_slot_is_never_touched(
        self, iso_state, clean_auth_env, monkeypatch
    ):
        monkeypatch.setattr(profiles, "set_request_profile", _boom)
        monkeypatch.setattr(profiles, "clear_request_profile", _boom)
        monkeypatch.setattr(profiles, "get_active_profile_name", _boom)
        _write(iso_state.state / ".signing_key", b"k" * 32)
        _write_session_store(iso_state.state, {"tok-1": time.time() + 3600})
        tls = profiles._tls
        before = getattr(tls, "profile", None)
        auth.read_only_auth_enabled()
        auth.read_only_incoming_cookie_session_info(_signed_cookie("tok-1", b"k" * 32))
        sig = hmac.new(b"k" * 32, b"profile:tok-1:alice", hashlib.sha256).hexdigest()
        auth.read_only_verify_profile_cookie(f"alice.{sig}", _signed_cookie("tok-1", b"k" * 32))
        assert getattr(tls, "profile", None) is before

    def test_no_files_created_or_written_by_any_seam(
        self, iso_state, clean_auth_env, monkeypatch
    ):
        monkeypatch.setenv("HERMES_WEBUI_PASSWORD", "pw")
        root = iso_state.state.parent
        before = _tree_snapshot(root)
        auth.read_only_auth_enabled()
        auth.read_only_incoming_cookie_session_info("anything.invalid")
        auth.read_only_verify_profile_cookie("alice.sig", "tok-1.sig")
        assert _tree_snapshot(root) == before
        assert not (iso_state.state / ".signing_key").exists()
        assert not (iso_state.state / ".pbkdf2_key").exists()
        assert not (iso_state.state / ".sessions.json").exists()
        assert not (iso_state.state / "settings.json").exists()
        assert not (iso_state.base / "profiles").exists()

    def test_process_caches_are_not_populated(
        self, iso_state, clean_auth_env, monkeypatch
    ):
        monkeypatch.setenv("HERMES_WEBUI_PASSWORD", "pw")
        _write(iso_state.state / ".signing_key", b"k" * 32)
        _write_session_store(iso_state.state, {"tok-1": time.time() + 3600})
        sessions_before = dict(auth._sessions)
        auth.read_only_auth_enabled()
        auth.read_only_incoming_cookie_session_info(_signed_cookie("tok-1", b"k" * 32))
        sig = hmac.new(b"k" * 32, b"profile:tok-1:alice", hashlib.sha256).hexdigest()
        auth.read_only_verify_profile_cookie(f"alice.{sig}", _signed_cookie("tok-1", b"k" * 32))
        assert auth._PBKDF2_KEY_CACHE is None
        assert auth._SIGNING_KEY_CACHE is None
        assert auth._AUTH_HASH_CACHE is None
        assert auth._AUTH_HASH_COMPUTED is False
        assert auth._sessions == sessions_before
