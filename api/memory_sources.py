"""Anchored byte-faithful raw Memory source reader (hermex #58, PR 1).

PR 1 scope — the module is exercised DIRECTLY by ``tests/test_memory_sources_pr1.py``.
There is deliberately **no public dispatch and no capability**: the route is not
reachable over HTTP and ``/api/system/health`` does not advertise
``memory_raw_v1`` until PR 2 (§16 of the v6 contract).

Contents (per §9/§10/§11 of the v6 binding contract):

- ``parse_raw_query`` — strict route-local query parsing (§4): percent-decode
  exactly once, strict UTF-8, no ``+``→space, duplicate/unknown/path/workspace/
  profile selectors rejected.
- ``validate_provenance`` — the §8 Host/Origin/Referer/Sec-Fetch/forwarded-header
  provenance policy as a pure helper.
- ``read_only_profile_config_snapshot(ctx)`` — the authorized Profile's
  ``config.yaml`` read directly through a bounded no-follow regular-file reader;
  never ``get_config()``/``get_config_snapshot()``/cache/process-global state.
- ``read_only_profile_default_workspace(ctx)`` — pure profile-local default
  workspace: ``last_workspace.txt`` then ``workspace``/``default_workspace``/
  ``terminal.cwd`` config keys; no mkdir, no migration, no process-global
  fallback, remote terminal backends return ``None``.
- ``read_only_session_metadata(ctx, session_id)`` — strict read-only WebUI
  session sidecar resolver for ``STATE_DIR/sessions/<id>.json`` (never the auth
  ``STATE_DIR/.sessions.json`` store); bounded 64 KiB prefix, no ``Session``
  instantiation, no legacy-facts/index/cache fallback.
- ``read_only_resolve_trusted_workspace(ctx, candidate)`` — route-safe
  companion to ``resolve_trusted_workspace()``: home carve-out, system-root
  rejection, and the profile-local saved-workspace list read directly; never
  ``load_workspaces()``/cleanup/migration/writers; remote-terminal candidates
  rejected.
- ``resolve_fixed_source(ctx, source, session_id=...)`` — the four fixed
  selectors with their feature gates and the workspace-first ascending
  candidate scan with the independently authorized nearest Git root (§9).
- ``read_anchored_source(anchor, components, limit)`` — the race-resistant
  bounded reader (§10): held anchor-parent/anchor FDs, component-wise
  ``O_NOFOLLOW`` dir_fd traversal, pre/post identity tuples, bounded short-read
  loop, fixed 200/404/409/413/503 outcomes.
- ``build_envelope`` / ``serialize_envelope`` / ``representation_etag`` — the
  §11 envelope and canonical serializer (``sort_keys=True``, compact
  separators, ``ensure_ascii=True``, ``allow_nan=False``, no trailing newline);
  source-byte ``checksum``/``source_version`` are deliberately distinct from the
  representation ``repr-sha256`` ETag.
- ``raw_max_bytes`` — the ``HERMES_WEBUI_MEMORY_RAW_MAX_BYTES`` deployment key
  (default 8 MiB, valid 1..16 MiB, invalid ⇒ ``None`` ⇒ 503 raw_unavailable).
- ``raw_read_slot`` / ``read_memory_source`` — the bounded 4-slot semaphore
  held across resolution→read→serialization and the module-level orchestration
  entry the PR 2 route will call.

No-mutation boundary (§5): every resolver takes the immutable
``AuthorizedRawProfileContext`` by parameter, never touches request-profile TLS
state, never consults the process active profile, never creates directories,
and never calls cache/discovery/migration/writer helpers.
"""

from __future__ import annotations

import base64
import contextlib
import dataclasses
import hashlib
import json
import os
import stat
import sys
import threading
from pathlib import Path

from api.auth import AuthorizedRawProfileContext, _read_regular_file_no_follow
from api.config import STATE_DIR
from api.workspace import _is_blocked_workspace_path

# ── Fixed selectors and size settings (§3/§10) ───────────────────────────────

SOURCES = ("memory", "user", "soul", "project_context")

DEFAULT_MAX_BYTES = 8388608  # 8 MiB when HERMES_WEBUI_MEMORY_RAW_MAX_BYTES is unset
MAX_LIMIT_BYTES = 16777216  # 16 MiB inclusive ceiling

SESSION_METADATA_MAX_BYTES = 65536  # §9 bounded sidecar prefix cap (64 KiB)
SESSION_ID_MAX_BYTES = 256  # §4 bounded session_id length
CONFIG_MAX_BYTES = 262144  # bounded profile config.yaml read
WORKSPACE_ENTRY_MAX_BYTES = 8192  # bounded last_workspace.txt read
WORKSPACES_MAX_BYTES = 262144  # bounded profile workspaces.json read

_SESSION_ID_SAFE_CHARS = frozenset(
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-"
)

# Race-safety capability (§10): the anchored reader needs dir_fd/openat
# traversal, O_NOFOLLOW/O_DIRECTORY/O_CLOEXEC/O_NONBLOCK, no-follow stats and
# descriptor identity. On platforms that cannot prove the equivalent the module
# fails closed with 503 raw_unavailable.
_RACE_SAFE_READ_SUPPORTED = (
    sys.platform != "win32"
    and hasattr(os, "O_NOFOLLOW")
    and hasattr(os, "O_DIRECTORY")
    and hasattr(os, "O_CLOEXEC")
    and hasattr(os, "O_NONBLOCK")
    and os.open in getattr(os, "supports_dir_fd", set())
    and os.stat in getattr(os, "supports_dir_fd", set())
    and os.stat in getattr(os, "supports_follow_symlinks", set())
)

_DIR_FLAGS = (
    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
)
_FILE_FLAGS = (
    os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
)

_READ_CHUNK = 65536

# Four process-local read slots (§10); held from before resolution through
# serialization; released on success and every error path.
_RAW_READ_SLOTS = threading.BoundedSemaphore(4)

_IDENTITY_KEYS = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")


# ── Outcome value objects ────────────────────────────────────────────────────


@dataclasses.dataclass(frozen=True)
class QueryResult:
    ok: bool
    source: str | None = None
    session_id: str | None = None


@dataclasses.dataclass(frozen=True)
class ProvenanceResult:
    ok: bool
    origin: str | None = None


@dataclasses.dataclass(frozen=True)
class SourceResolution:
    ok: bool
    source: str | None = None
    anchor: Path | None = None
    components: tuple[str, ...] | None = None
    name: str | None = None
    content_type: str | None = None
    error: str | None = None  # 'invalid_request' | 'forbidden' | 'not_found'


@dataclasses.dataclass(frozen=True)
class ReadOutcome:
    status: int  # 200 | 404 | 409 | 413 | 503
    data: bytes | None = None
    error: str | None = None  # 'not_found' | 'source_changed' | 'source_too_large' | 'raw_unavailable'


@dataclasses.dataclass(frozen=True)
class SourceReadOutcome:
    status: int
    error: str | None = None
    envelope: dict | None = None
    body: bytes | None = None
    etag: str | None = None
    retry_after: str | None = None


# ── Small pure helpers ───────────────────────────────────────────────────────


def _identity(st: os.stat_result) -> tuple:
    return tuple(getattr(st, key) for key in _IDENTITY_KEYS)


def _safe_resolve(path: Path) -> Path:
    try:
        return path.resolve()
    except (OSError, RuntimeError, ValueError):
        return path


def _expand_user(path: str) -> Path:
    return Path(os.path.expanduser(path))


def _home_dir() -> Path:
    """Env-aware effective home (mirrors ``api.workspace._home_path``)."""
    raw = (
        os.environ.get("HOME")
        or os.environ.get("USERPROFILE")
        or (os.environ.get("HOMEDRIVE") or "") + (os.environ.get("HOMEPATH") or "")
        or str(Path.home())
    )
    return _safe_resolve(Path(raw))


def _is_directory(path: Path) -> bool:
    try:
        return stat.S_ISDIR(path.stat().st_mode)
    except OSError:
        return False


def _config_truthy(value) -> bool:
    """Mirror of the existing ``_webui_truthy`` gate semantics (#6406)."""
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _profile_state_dir(ctx: AuthorizedRawProfileContext) -> Path:
    """Pure profile-state directory derivation — never ``_profile_state_dir()``.

    The default Profile owns the global WebUI state directory; a named Profile
    owns ``{profile_home}/webui_state``. Never creates the directory.
    """
    if ctx.bound_profile == "default":
        return STATE_DIR
    return ctx.profile_home / "webui_state"


# ── Strict query parsing (§4) ────────────────────────────────────────────────

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def _strict_percent_decode(value: str) -> str | None:
    """Percent-decode exactly once with strict syntax and strict UTF-8.

    A literal ``+`` remains ``+``. Non-ASCII literal characters, malformed
    escapes, invalid UTF-8, and NUL/control characters fail closed (``None``).
    """
    out = bytearray()
    i = 0
    n = len(value)
    while i < n:
        ch = value[i]
        if ch == "%":
            if i + 2 >= n or value[i + 1] not in _HEX_DIGITS or value[i + 2] not in _HEX_DIGITS:
                return None
            out.append(int(value[i + 1 : i + 3], 16))
            i += 3
        else:
            code = ord(ch)
            if code > 0x7F:
                return None
            out.append(code)
            i += 1
    try:
        decoded = out.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in decoded):
        return None
    return decoded


def parse_raw_query(raw: str) -> QueryResult:
    """Strict route-local query parse (§4). ``source`` required exactly once;
    ``session_id`` optional, exactly once, only for ``project_context``."""
    if not isinstance(raw, str) or not raw:
        return QueryResult(ok=False)
    seen: set[str] = set()
    source: str | None = None
    session_id: str | None = None
    for field in raw.split("&"):
        if "=" not in field:
            return QueryResult(ok=False)
        raw_name, raw_value = field.split("=", 1)
        name = _strict_percent_decode(raw_name)
        value = _strict_percent_decode(raw_value)
        if name is None or value is None or not name or not value:
            return QueryResult(ok=False)
        if name in seen:
            return QueryResult(ok=False)
        seen.add(name)
        if name == "source":
            if source is not None:
                return QueryResult(ok=False)
            source = value
        elif name == "session_id":
            if session_id is not None:
                return QueryResult(ok=False)
            session_id = value
        else:
            # Unknown names — including path/workspace/profile selectors — are rejected.
            return QueryResult(ok=False)
    if source is None or source not in SOURCES:
        return QueryResult(ok=False)
    if session_id is not None:
        if source != "project_context":
            return QueryResult(ok=False)
        if not _safe_session_id(session_id) or len(session_id) > SESSION_ID_MAX_BYTES:
            return QueryResult(ok=False)
    return QueryResult(ok=True, source=source, session_id=session_id)


def _safe_session_id(sid: str) -> bool:
    return bool(sid) and all(c in _SESSION_ID_SAFE_CHARS for c in sid)


# ── Provenance validation (§8) ───────────────────────────────────────────────


def _parse_port(value: str) -> int | None:
    if not value.isascii() or not value.isdigit() or len(value) > 5:
        return None
    port = int(value)
    if not (1 <= port <= 65535):
        return None
    return port


def _valid_ipv6(value: str) -> bool:
    if not value or ":" not in value:
        return False
    return all(c in "0123456789abcdefABCDEF:." for c in value)


def _valid_dns_host(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    if not all(c.isascii() and (c.isalnum() or c in "-.") for c in host):
        return False
    if host.startswith("-") or host.endswith("-"):
        return False
    if ".." in host:
        return False
    return True


def _parse_host(value: str) -> tuple[str, int | None] | None:
    """Strict single Host value: no list/whitespace/userinfo/path/query."""
    v = value.strip()
    if not v or any(ch.isspace() for ch in v):
        return None
    if "," in v or "@" in v or "/" in v or "?" in v or "#" in v:
        return None
    if v.startswith("["):
        end = v.find("]")
        if end == -1:
            return None
        ipv6 = v[1:end]
        rest = v[end + 1 :]
        if not _valid_ipv6(ipv6):
            return None
        port = None
        if rest:
            if not rest.startswith(":"):
                return None
            port = _parse_port(rest[1:])
            if port is None:
                return None
        return (f"[{ipv6.lower()}]", port)
    if ":" in v:
        host_part, _, port_part = v.rpartition(":")
        if not host_part or ":" in host_part:
            return None
        port = _parse_port(port_part)
        if port is None:
            return None
        host = host_part.lower()
    else:
        host = v.lower()
        port = None
    if not _valid_dns_host(host):
        return None
    return (host, port)


def _effective_port(scheme: str, port: int | None) -> int:
    if port is not None:
        return port
    return 443 if scheme == "https" else 80


def _format_origin(scheme: str, host: str, port: int | None) -> str:
    if port is not None and not (
        (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    ):
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"


def _parse_origin(value: str) -> tuple[str, str, int] | None:
    v = value.strip()
    if "://" not in v:
        return None
    scheme, rest = v.split("://", 1)
    if scheme.lower() != scheme or scheme not in ("http", "https"):
        return None
    if not rest or "@" in rest or any(c in rest for c in ("/", "?", "#")):
        return None
    host_port = _parse_host(rest)
    if host_port is None:
        return None
    host, port = host_port
    return (scheme, host, _effective_port(scheme, port))


def _parse_referer_origin(value: str) -> tuple[str, str, int] | None:
    v = value.strip()
    if "://" not in v:
        return None
    scheme, rest = v.split("://", 1)
    if scheme.lower() != scheme or scheme not in ("http", "https"):
        return None
    authority = rest
    for sep in ("/", "?", "#"):
        idx = authority.find(sep)
        if idx != -1:
            authority = authority[:idx]
            break
    if "@" in authority:
        return None
    host_port = _parse_host(authority)
    if host_port is None:
        return None
    host, port = host_port
    return (scheme, host, _effective_port(scheme, port))


def validate_provenance(
    fields,
    *,
    tls: bool = False,
    trust_forwarded_proto: bool = False,
    trust_forwarded_host: bool = False,
) -> ProvenanceResult:
    """§8 steps 5-8 as a pure helper over received ``(name, value)`` fields.

    ``fields`` is the received header list in order (duplicate field names
    preserved). Returns ``ok`` with the canonical external origin, or a
    fail-closed rejection.
    """
    groups: dict[str, list[str]] = {}
    for name, value in fields:
        groups.setdefault(name.lower(), []).append(value)

    host_values = groups.get("host", [])
    if len(host_values) != 1:
        return ProvenanceResult(ok=False)
    host_port = _parse_host(host_values[0])
    if host_port is None:
        return ProvenanceResult(ok=False)
    host, port = host_port

    scheme = "https" if tls else "http"
    forwarded_proto = groups.get("x-forwarded-proto", [])
    if trust_forwarded_proto:
        if (
            len(forwarded_proto) != 1
            or "," in forwarded_proto[0]
            or forwarded_proto[0].strip().lower() not in ("http", "https")
        ):
            return ProvenanceResult(ok=False)
        scheme = forwarded_proto[0].strip().lower()
    forwarded_host = groups.get("x-forwarded-host", [])
    if trust_forwarded_host:
        if len(forwarded_host) != 1 or "," in forwarded_host[0]:
            return ProvenanceResult(ok=False)
        fwd = _parse_host(forwarded_host[0])
        if fwd is None:
            return ProvenanceResult(ok=False)
        host, port = fwd

    canonical = (scheme, host, _effective_port(scheme, port))

    origins = groups.get("origin", [])
    if len(origins) > 1:
        return ProvenanceResult(ok=False)
    if origins:
        parsed = _parse_origin(origins[0])
        if parsed is None or parsed != canonical:
            return ProvenanceResult(ok=False)

    referers = groups.get("referer", [])
    if len(referers) > 1:
        return ProvenanceResult(ok=False)
    if referers:
        parsed = _parse_referer_origin(referers[0])
        if parsed is None or parsed != canonical:
            return ProvenanceResult(ok=False)

    fetch = {name: values for name, values in groups.items() if name.startswith("sec-fetch-")}
    if fetch:
        allowed_names = ("sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest")
        for name, values in fetch.items():
            if name not in allowed_names or len(values) != 1:
                return ProvenanceResult(ok=False)
            value = values[0].strip()
            if not value or "," in value or any(ch.isspace() for ch in value):
                return ProvenanceResult(ok=False)
        site = fetch.get("sec-fetch-site")
        if site is None or site[0].strip() != "same-origin":
            return ProvenanceResult(ok=False)
        mode = fetch.get("sec-fetch-mode")
        if mode is not None and mode[0].strip() not in ("cors", "same-origin"):
            return ProvenanceResult(ok=False)
        dest = fetch.get("sec-fetch-dest")
        if dest is not None and dest[0].strip() != "empty":
            return ProvenanceResult(ok=False)

    return ProvenanceResult(ok=True, origin=_format_origin(scheme, host, port))


# ── Profile config snapshot and feature gates (§9) ──────────────────────────


def read_only_profile_config_snapshot(ctx: AuthorizedRawProfileContext) -> dict:
    """The authorized Profile's ``config.yaml`` as a detached mapping.

    Direct bounded no-follow read only. Missing or malformed ``memory`` config
    maps to defaults (enabled); malformed YAML/non-mapping/symlink/oversized/
    unreadable files yield ``{}`` (fail closed). Never calls ``get_config()``,
    ``get_config_snapshot()``, ``_refresh_config_cache()``, ``_cfg_cache``,
    process-global config aliases, or any writer.
    """
    raw = _read_regular_file_no_follow(ctx.profile_home / "config.yaml", CONFIG_MAX_BYTES)
    if raw is None:
        return {}
    try:
        import yaml

        loaded = yaml.safe_load(raw.decode("utf-8"))
    except Exception:
        return {}
    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        return {}
    return loaded


def source_feature_gate(ctx: AuthorizedRawProfileContext, source: str) -> str | None:
    """§9 per-Profile feature gates. Returns ``'forbidden'`` or ``None``."""
    if source not in ("memory", "user"):
        return None
    cfg = read_only_profile_config_snapshot(ctx)
    memory_cfg = cfg.get("memory")
    if not isinstance(memory_cfg, dict):
        return None  # missing/malformed memory config defaults to enabled
    if source == "memory":
        enabled = _config_truthy(memory_cfg.get("memory_enabled", True))
    else:
        enabled = _config_truthy(memory_cfg.get("user_profile_enabled", True))
    return None if enabled else "forbidden"


# ── Default workspace resolver (§9) ─────────────────────────────────────────


def read_only_profile_default_workspace(ctx: AuthorizedRawProfileContext) -> Path | None:
    """Pure profile-local default workspace for ``project_context`` without a
    session. Reads only this Profile's ``last_workspace.txt`` and its own config
    keys (``workspace``, ``default_workspace``, then ``terminal.cwd``).

    Never calls ``_profile_default_workspace()`` fallback mode,
    ``get_last_workspace()``, ``load_workspaces()``, ``_migrate_global_workspaces()``,
    the global ``LAST_WORKSPACE_FILE``, ``TERMINAL_CWD``, process CWD, or global
    ``DEFAULT_WORKSPACE``. Never creates a directory or migrates state. A
    remote/non-local terminal backend, or a missing/empty/malformed/
    non-directory/invalid default, returns ``None``.
    """
    cfg = read_only_profile_config_snapshot(ctx)
    terminal_cfg = cfg.get("terminal")
    if isinstance(terminal_cfg, dict):
        backend = str(terminal_cfg.get("backend") or "").strip().lower()
        if backend not in ("", "local"):
            return None  # remote/non-local terminal backend: unsupported

    # 1. Profile-scoped last_workspace.txt (default Profile owns the global state dir).
    last_workspace_raw = _read_regular_file_no_follow(
        _profile_state_dir(ctx) / "last_workspace.txt", WORKSPACE_ENTRY_MAX_BYTES
    )
    if last_workspace_raw is not None:
        try:
            text = last_workspace_raw.decode("utf-8", errors="strict").strip()
        except UnicodeDecodeError:
            return None  # malformed state fails closed
        if text:
            candidate = _safe_resolve(_expand_user(text))
            if _is_directory(candidate):
                return candidate

    # 2. Config keys in the existing precedence: workspace, default_workspace, terminal.cwd.
    for key in ("workspace", "default_workspace"):
        value = cfg.get(key)
        if isinstance(value, str) and value.strip():
            candidate = _safe_resolve(_expand_user(value.strip()))
            if _is_directory(candidate):
                return candidate
    if isinstance(terminal_cfg, dict):
        cwd = terminal_cfg.get("cwd")
        if isinstance(cwd, str) and cwd.strip() and cwd.strip() not in (".",):
            candidate = _safe_resolve(_expand_user(cwd.strip()))
            if _is_directory(candidate):
                return candidate
    return None


# ── Read-only session metadata (§9) ─────────────────────────────────────────


def read_only_session_metadata(
    ctx: AuthorizedRawProfileContext, session_id: str
) -> dict | None:
    """Strict read-only WebUI session sidecar resolver.

    Reads ``STATE_DIR/sessions/<session_id>.json`` (the WebUI sidecar store —
    never the auth ``STATE_DIR/.sessions.json``) through a no-follow descriptor
    with a bounded 64 KiB prefix. Requires the bounded safe session-ID grammar,
    an exact matching ``session_id``, a bounded metadata prefix containing
    ``workspace``, and a ``profile`` field (missing/empty is the root/default
    alias). Never instantiates ``Session`` and never calls ``get_session()``,
    ``Session.load()``, ``Session.load_metadata_only()``, legacy-facts/index
    fallbacks, or any full-session parser. Returns ``{'workspace', 'profile'}``
    or ``None`` (missing/malformed/over-cap/foreign/blank-workspace).
    """
    if not isinstance(session_id, str) or not _safe_session_id(session_id):
        return None
    if len(session_id) > SESSION_ID_MAX_BYTES:
        return None
    raw = _read_regular_file_no_follow(
        STATE_DIR / "sessions" / f"{session_id}.json", SESSION_METADATA_MAX_BYTES
    )
    if raw is None:
        return None
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    workspace_value = data.get("workspace")
    if not isinstance(workspace_value, str) or not workspace_value.strip():
        return None
    profile_value = data.get("profile")
    if profile_value is None:
        profile_value = ""
    if not isinstance(profile_value, str):
        return None
    normalized = "default" if profile_value.strip() == "" else profile_value.strip()
    if normalized != ctx.bound_profile:
        return None
    return {"workspace": workspace_value.strip(), "profile": normalized}


# ── Trusted workspace resolver (§9) ─────────────────────────────────────────


def _read_profile_saved_workspaces(ctx: AuthorizedRawProfileContext) -> set[str] | None:
    """Direct read of the Profile-local saved-workspace list.

    Missing file ⇒ empty set (readable). Malformed/unreadable/symlinked state
    ⇒ ``None`` (fail closed, no fallback candidate). Never calls
    ``load_workspaces()``, ``_clean_workspace_list()``,
    ``_migrate_global_workspaces()``, ``_profile_state_dir()``, or any writer.
    """
    raw = _read_regular_file_no_follow(
        _profile_state_dir(ctx) / "workspaces.json", WORKSPACES_MAX_BYTES
    )
    if raw is None:
        return set()
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(data, list):
        return None
    out: set[str] = set()
    for entry in data:
        if isinstance(entry, dict) and isinstance(entry.get("path"), str) and entry["path"]:
            out.add(str(_safe_resolve(_expand_user(entry["path"]))))
    return out


def read_only_resolve_trusted_workspace(
    ctx: AuthorizedRawProfileContext, candidate
) -> Path | None:
    """Route-safe companion to ``resolve_trusted_workspace()`` (§9).

    Accepts a non-empty candidate only and applies the same home carve-out,
    system-root rejection, and profile-saved-workspace trust decisions under
    the authorized context. Remote-terminal candidates are rejected (this
    endpoint reads local filesystem bytes). Malformed/unreadable workspace
    state fails closed; the caller receives no fallback candidate. Never
    creates state, persists cleanup, migrates the global workspace file, uses
    the global default workspace as a selection fallback, or calls
    cache/discovery helpers.
    """
    if candidate is None:
        return None
    if isinstance(candidate, Path):
        raw = str(candidate)
    elif isinstance(candidate, str):
        raw = candidate
    else:
        return None
    if not raw.strip():
        return None
    cfg = read_only_profile_config_snapshot(ctx)
    terminal_cfg = cfg.get("terminal")
    if isinstance(terminal_cfg, dict):
        backend = str(terminal_cfg.get("backend") or "").strip().lower()
        if backend not in ("", "local"):
            return None
    path = _safe_resolve(_expand_user(raw.strip()))
    try:
        st = path.stat()
    except OSError:
        return None
    if not stat.S_ISDIR(st.st_mode):
        return None
    home = _home_dir()
    if home != Path("/"):
        try:
            path.relative_to(home)
            return path
        except ValueError:
            pass
    if _is_blocked_workspace_path(path, raw):
        return None
    saved = _read_profile_saved_workspaces(ctx)
    if saved is not None and str(path) in saved:
        return path
    return None


# ── Fixed source resolution and candidate scan (§9) ─────────────────────────


def _nearest_git_root(start: Path) -> Path | None:
    """Nearest ancestor (inclusive) containing a ``.git`` entry (dir or file)."""
    current = start
    while True:
        try:
            st = (current / ".git").lstat()
        except OSError:
            st = None
        if st is not None and (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)):
            return current
        if current.parent == current:
            return None
        current = current.parent


def _rel_components(scan_root: Path, level: Path) -> tuple[str, ...]:
    try:
        return tuple(level.relative_to(scan_root).parts)
    except ValueError:
        return ()


def _valid_components(components) -> bool:
    if not isinstance(components, tuple) or not components:
        return False
    for comp in components:
        if not isinstance(comp, str) or not comp:
            return False
        if comp in (".", "..") or "/" in comp or "\\" in comp or "\x00" in comp:
            return False
    return True


def _stat_regular_no_follow(anchor: Path, components: tuple[str, ...]) -> bool:
    """No-follow component-wise stat used by the candidate scan (§9).

    The authoritative read re-validates everything with held descriptors; this
    selection helper only decides *which* candidate wins and must never select
    a symlink/non-regular/missing component.
    """
    if not _RACE_SAFE_READ_SUPPORTED or not _valid_components(components):
        return False
    parent = anchor.parent
    fds: list[int] = []
    try:
        try:
            parent_fd = os.open(parent, _DIR_FLAGS)
        except OSError:
            return False
        fds.append(parent_fd)
        try:
            st = os.stat(anchor.name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError:
            return False
        if not stat.S_ISDIR(st.st_mode):
            return False
        try:
            anchor_fd = os.open(anchor.name, _DIR_FLAGS, dir_fd=parent_fd)
        except OSError:
            return False
        fds.append(anchor_fd)
        current = anchor_fd
        for comp in components[:-1]:
            try:
                st = os.stat(comp, dir_fd=current, follow_symlinks=False)
            except OSError:
                return False
            if not stat.S_ISDIR(st.st_mode):
                return False
            try:
                fd = os.open(comp, _DIR_FLAGS, dir_fd=current)
            except OSError:
                return False
            fds.append(fd)
            current = fd
        try:
            st = os.stat(components[-1], dir_fd=current, follow_symlinks=False)
        except OSError:
            return False
        return stat.S_ISREG(st.st_mode)
    finally:
        for fd in reversed(fds):
            try:
                os.close(fd)
            except OSError:
                pass


def _list_dir_no_follow(anchor: Path, components: tuple[str, ...]) -> list[str] | None:
    """List a directory reached through a no-follow component chain."""
    if not _RACE_SAFE_READ_SUPPORTED or not _valid_components(components):
        return None
    parent = anchor.parent
    fds: list[int] = []
    try:
        try:
            parent_fd = os.open(parent, _DIR_FLAGS)
        except OSError:
            return None
        fds.append(parent_fd)
        try:
            st = os.stat(anchor.name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError:
            return None
        if not stat.S_ISDIR(st.st_mode):
            return None
        try:
            anchor_fd = os.open(anchor.name, _DIR_FLAGS, dir_fd=parent_fd)
        except OSError:
            return None
        fds.append(anchor_fd)
        current = anchor_fd
        for comp in components:
            try:
                st = os.stat(comp, dir_fd=current, follow_symlinks=False)
            except OSError:
                return None
            if not stat.S_ISDIR(st.st_mode):
                return None
            try:
                fd = os.open(comp, _DIR_FLAGS, dir_fd=current)
            except OSError:
                return None
            fds.append(fd)
            current = fd
        try:
            return os.listdir(current)
        except OSError:
            return None
    finally:
        for fd in reversed(fds):
            try:
                os.close(fd)
            except OSError:
                pass


def _content_type_for_name(name: str) -> str:
    if name.endswith(".md") or name.endswith(".mdc"):
        return "text/markdown"
    return "text/plain"


def _scan_project_candidates(
    workspace: Path, scan_root: Path
) -> tuple[Path, tuple[str, ...], str] | None:
    """§9 fixed candidate order: workspace-first ascending to the authorized
    Git root; then trusted-level fallback names; then sorted ``.cursor/rules``
    ``*.mdc``. Returns ``(anchor, components, name)`` of the first valid
    regular file, or ``None``.
    """
    levels: list[Path] = []
    current = workspace
    while True:
        levels.append(current)
        if current == scan_root:
            break
        current = current.parent

    for level in levels:
        prefix = _rel_components(scan_root, level)
        for name in (".hermes.md", "HERMES.md"):
            components = prefix + (name,)
            if _stat_regular_no_follow(scan_root, components):
                return (scan_root, components, name)
    prefix = _rel_components(scan_root, workspace)
    for name in ("AGENTS.md", "agents.md", "CLAUDE.md", "claude.md", ".cursorrules"):
        components = prefix + (name,)
        if _stat_regular_no_follow(scan_root, components):
            return (scan_root, components, name)
    rules_prefix = prefix + (".cursor", "rules")
    entries = _list_dir_no_follow(scan_root, rules_prefix)
    if entries is not None:
        for name in sorted(entries):
            if name.endswith(".mdc"):
                components = rules_prefix + (name,)
                if _stat_regular_no_follow(scan_root, components):
                    return (scan_root, components, name)
    return None


def _resolution_ok(
    source: str, anchor: Path, components: tuple[str, ...], name: str
) -> SourceResolution:
    return SourceResolution(
        ok=True,
        source=source,
        anchor=anchor,
        components=components,
        name=name,
        content_type=_content_type_for_name(name),
    )


def resolve_fixed_source(
    ctx: AuthorizedRawProfileContext,
    source: str,
    *,
    session_id: str | None = None,
) -> SourceResolution:
    """Resolve one of the four fixed selectors to an anchored source (§9).

    The anchor is the independently authorized scan root (the Profile home for
    ``memory``/``user``/``soul``; the trusted workspace or independently
    authorized nearest Git root for ``project_context``). Returns
    ``(anchor, components, name, content_type)`` on success, or
    ``invalid_request``/``forbidden``/``not_found``.
    """
    if source not in SOURCES:
        return SourceResolution(ok=False, error="invalid_request")
    gate = source_feature_gate(ctx, source)
    if gate is not None:
        return SourceResolution(ok=False, error=gate)
    if source == "memory":
        return _resolution_ok(source, ctx.profile_home, ("memories", "MEMORY.md"), "MEMORY.md")
    if source == "user":
        return _resolution_ok(source, ctx.profile_home, ("memories", "USER.md"), "USER.md")
    if source == "soul":
        return _resolution_ok(source, ctx.profile_home, ("SOUL.md",), "SOUL.md")

    # project_context: session workspace or profile-local default workspace.
    if session_id is not None:
        meta = read_only_session_metadata(ctx, session_id)
        if meta is None:
            return SourceResolution(ok=False, error="not_found")
        candidate = meta["workspace"]
    else:
        candidate = read_only_profile_default_workspace(ctx)
        if candidate is None:
            return SourceResolution(ok=False, error="not_found")
    workspace = read_only_resolve_trusted_workspace(ctx, candidate)
    if workspace is None:
        return SourceResolution(ok=False, error="not_found")

    # Second authorization: the nearest Git root (inclusive) is independently
    # authorized before any ancestor candidate is inspected.
    scan_root = workspace
    git_root = _nearest_git_root(workspace)
    if git_root is not None and git_root != workspace:
        if read_only_resolve_trusted_workspace(ctx, git_root) is not None:
            scan_root = git_root

    found = _scan_project_candidates(workspace, scan_root)
    if found is None:
        return SourceResolution(ok=False, error="not_found")
    anchor, components, name = found
    return _resolution_ok(source, anchor, components, name)


# ── Race-resistant bounded reader (§10) ─────────────────────────────────────


def _raw_read(fd: int, n: int) -> bytes:
    """Test seam: the single read primitive of the bounded short-read loop."""
    return os.read(fd, n)


def read_anchored_source(
    anchor: Path, components: tuple[str, ...], limit: int
) -> ReadOutcome:
    """Anchored, component-wise, no-follow bounded read (§10).

    Holds the anchor's lexical parent directory FD from before the anchor open
    through the post-read check, opens every namespace component relative to a
    held parent FD with ``O_NOFOLLOW|O_DIRECTORY`` (final:
    ``O_NOFOLLOW|O_NONBLOCK``), and compares the full identity tuple
    ``(st_dev, st_ino, st_mode, st_size, st_mtime_ns, st_ctime_ns)`` for every
    entry/descriptor before and after reading.

    Outcomes: ``200`` stable bytes; ``404`` missing/non-regular/symlinked/
    denied component; ``409`` source_changed (delete/unlink, symlink swap,
    atomic replacement, parent/component swap, in-place identity/metadata
    change, EOF before the stable size); ``413`` source_too_large (limit+1
    bytes obtained, no partial data); ``503`` raw_unavailable (unsupported
    platform or invalid limit). Mutation/race checks take precedence over a
    success or 413 result.
    """
    if not _RACE_SAFE_READ_SUPPORTED:
        return ReadOutcome(status=503, error="raw_unavailable")
    if not isinstance(limit, int) or limit < 1:
        return ReadOutcome(status=503, error="raw_unavailable")
    if not isinstance(anchor, Path) or not anchor.is_absolute() or anchor == Path("/"):
        # A root anchor has no stable held parent entry; refuse it.
        return ReadOutcome(status=503, error="raw_unavailable")
    if not _valid_components(components):
        return ReadOutcome(status=404, error="not_found")

    parent = anchor.parent
    try:
        parent_fd = os.open(parent, _DIR_FLAGS)
    except OSError:
        return ReadOutcome(status=404, error="not_found")
    held: list[int] = [parent_fd]
    try:
        # Anchor: no-follow stat from the held parent, open relative to it,
        # immediately compare the descriptor identity to the entry.
        try:
            anchor_entry_pre = os.stat(anchor.name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError:
            return ReadOutcome(status=404, error="not_found")
        if not stat.S_ISDIR(anchor_entry_pre.st_mode):
            return ReadOutcome(status=404, error="not_found")
        try:
            anchor_fd = os.open(anchor.name, _DIR_FLAGS, dir_fd=parent_fd)
        except OSError:
            return ReadOutcome(status=404, error="not_found")
        held.append(anchor_fd)
        anchor_fd_pre = os.fstat(anchor_fd)
        if _identity(anchor_fd_pre) != _identity(anchor_entry_pre):
            return ReadOutcome(status=409, error="source_changed")

        # Nested namespace components, one at a time relative to the held parent.
        dir_pre: list[tuple[str, int, os.stat_result, int, os.stat_result]] = []
        current = anchor_fd
        for comp in components[:-1]:
            try:
                st = os.stat(comp, dir_fd=current, follow_symlinks=False)
            except OSError:
                return ReadOutcome(status=404, error="not_found")
            if not stat.S_ISDIR(st.st_mode):
                return ReadOutcome(status=404, error="not_found")
            try:
                fd = os.open(comp, _DIR_FLAGS, dir_fd=current)
            except OSError:
                return ReadOutcome(status=404, error="not_found")
            held.append(fd)
            fd_pre = os.fstat(fd)
            if _identity(fd_pre) != _identity(st):
                return ReadOutcome(status=409, error="source_changed")
            dir_pre.append((comp, current, st, fd, fd_pre))
            current = fd

        # Final entry: must be a regular file, opened no-follow/nonblocking.
        try:
            final_entry_pre = os.stat(components[-1], dir_fd=current, follow_symlinks=False)
        except OSError:
            return ReadOutcome(status=404, error="not_found")
        if not stat.S_ISREG(final_entry_pre.st_mode):
            return ReadOutcome(status=404, error="not_found")
        try:
            file_fd = os.open(components[-1], _FILE_FLAGS, dir_fd=current)
        except OSError:
            return ReadOutcome(status=404, error="not_found")
        held.append(file_fd)
        file_fd_pre = os.fstat(file_fd)
        if not stat.S_ISREG(file_fd_pre.st_mode):
            return ReadOutcome(status=404, error="not_found")
        if _identity(file_fd_pre) != _identity(final_entry_pre):
            return ReadOutcome(status=409, error="source_changed")

        # Bounded short-read loop: continue past positive short reads until
        # true EOF or limit+1 bytes; never more than limit+1 bytes are read.
        chunks: list[bytes] = []
        total = 0
        over = False
        try:
            while True:
                remaining = limit + 1 - total
                if remaining <= 0:
                    over = True
                    break
                chunk = _raw_read(file_fd, min(_READ_CHUNK, remaining))
                if not chunk:
                    break
                total += len(chunk)
                chunks.append(chunk)
                if total > limit:
                    over = True
                    break
        except OSError:
            return ReadOutcome(status=409, error="source_changed")

        # Post-read descriptor and namespace checks for every held entry.
        try:
            if _identity(os.fstat(anchor_fd)) != _identity(anchor_fd_pre):
                return ReadOutcome(status=409, error="source_changed")
            if (
                _identity(
                    os.stat(anchor.name, dir_fd=parent_fd, follow_symlinks=False)
                )
                != _identity(anchor_entry_pre)
            ):
                return ReadOutcome(status=409, error="source_changed")
            for comp, comp_parent_fd, st, fd, fd_pre in dir_pre:
                if _identity(os.fstat(fd)) != _identity(fd_pre):
                    return ReadOutcome(status=409, error="source_changed")
                if (
                    _identity(os.stat(comp, dir_fd=comp_parent_fd, follow_symlinks=False))
                    != _identity(st)
                ):
                    return ReadOutcome(status=409, error="source_changed")
            if _identity(os.fstat(file_fd)) != _identity(file_fd_pre):
                return ReadOutcome(status=409, error="source_changed")
            if (
                _identity(
                    os.stat(components[-1], dir_fd=current, follow_symlinks=False)
                )
                != _identity(final_entry_pre)
            ):
                return ReadOutcome(status=409, error="source_changed")
        except OSError:
            return ReadOutcome(status=409, error="source_changed")

        if over:
            return ReadOutcome(status=413, error="source_too_large")
        if total != file_fd_pre.st_size:
            # EOF arrived before the captured stable size.
            return ReadOutcome(status=409, error="source_changed")
        return ReadOutcome(status=200, data=b"".join(chunks))
    finally:
        for fd in reversed(held):
            try:
                os.close(fd)
            except OSError:
                pass


# ── Envelope and canonical serializer (§11) ─────────────────────────────────


def build_envelope(source: str, name: str, content_type: str, data: bytes) -> dict:
    """§11 byte-faithful envelope. ``checksum``/``source_version`` are SHA-256
    over the original source bytes and stay source identity even when the
    response representation carries a different ``name``."""
    digest = hashlib.sha256(data).hexdigest()
    return {
        "schema_version": 1,
        "source": source,
        "name": name,
        "content_type": content_type,
        "byte_length": len(data),
        "byte_encoding": "base64",
        "data": base64.b64encode(data).decode("ascii"),
        "checksum": {"algorithm": "sha-256", "value": digest},
        "source_version": f"sha256:{digest}",
    }


def serialize_envelope(envelope: dict) -> bytes:
    """The exact canonical 200 representation: sort_keys, compact separators,
    ``ensure_ascii``, no NaN tokens, UTF-8, no trailing newline."""
    return json.dumps(
        envelope,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def representation_etag(body: bytes) -> str:
    """Quoted strong representation ETag over the complete canonical 200 bytes.

    Deliberately distinct from the source-byte ``checksum``/``source_version``
    so a stable byte-identical project file whose selected candidate ``name``
    changes cannot produce a false 304.
    """
    return f'"repr-sha256:{hashlib.sha256(body).hexdigest()}"'


# ── Limit configuration and read slots (§10) ────────────────────────────────


def raw_max_bytes() -> int | None:
    """The deployment limit ``HERMES_WEBUI_MEMORY_RAW_MAX_BYTES``.

    Unset ⇒ 8 MiB. Present values must be ASCII decimal digits only and parse
    to an integer in ``1..16777216``; any invalid/out-of-range value returns
    ``None`` (the route maps it to 503 ``raw_unavailable``; nothing is clamped
    or defaulted).
    """
    value = os.getenv("HERMES_WEBUI_MEMORY_RAW_MAX_BYTES")
    if value is None:
        return DEFAULT_MAX_BYTES
    if not value.isascii() or not value.isdigit():
        return None
    parsed = int(value)
    if not (1 <= parsed <= MAX_LIMIT_BYTES):
        return None
    return parsed


@contextlib.contextmanager
def raw_read_slot():
    """One of four process-local read slots; yields ``False`` when exhausted.

    The slot is held from before source resolution/read through JSON
    serialization and is always released on success and every error path.
    """
    acquired = _RAW_READ_SLOTS.acquire(blocking=False)
    if not acquired:
        yield False
        return
    try:
        yield True
    finally:
        _RAW_READ_SLOTS.release()


def read_memory_source(
    ctx: AuthorizedRawProfileContext,
    source: str,
    *,
    session_id: str | None = None,
    limit: int | None = None,
) -> SourceReadOutcome:
    """PR 1 module-level orchestration: slot → gate → resolve → read → envelope.

    The PR 2 route calls this after its authentication/provenance gate; the
    module itself performs no HTTP work. ``limit`` defaults to
    ``raw_max_bytes()``; an invalid configured limit is 503 ``raw_unavailable``.
    """
    if limit is None:
        limit = raw_max_bytes()
    if not isinstance(limit, int) or limit < 1:
        return SourceReadOutcome(status=503, error="raw_unavailable")
    with raw_read_slot() as slot:
        if not slot:
            return SourceReadOutcome(status=503, error="raw_read_busy", retry_after="1")
        resolution = resolve_fixed_source(ctx, source, session_id=session_id)
        if not resolution.ok:
            status = {"invalid_request": 400, "forbidden": 403, "not_found": 404}.get(
                resolution.error or "", 500
            )
            return SourceReadOutcome(status=status, error=resolution.error)
        assert resolution.anchor is not None
        assert resolution.components is not None
        assert resolution.source is not None
        assert resolution.name is not None
        assert resolution.content_type is not None
        read = read_anchored_source(resolution.anchor, resolution.components, limit)
        if read.status != 200:
            return SourceReadOutcome(status=read.status, error=read.error)
        assert read.data is not None
        envelope = build_envelope(
            resolution.source, resolution.name, resolution.content_type, read.data
        )
        body = serialize_envelope(envelope)
        return SourceReadOutcome(
            status=200,
            envelope=envelope,
            body=body,
            etag=representation_etag(body),
        )
