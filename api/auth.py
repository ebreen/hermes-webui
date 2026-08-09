"""
Hermes Web UI -- optional authentication.
Off by default. Enable by setting HERMES_WEBUI_PASSWORD, configuring a
password in Settings, registering passkeys, or configuring native OIDC SSO.
"""
import hashlib
import hmac
import http.cookies
import json
import logging
import os
import re
import secrets
import stat
import tempfile
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from api.config import STATE_DIR, get_config, load_settings

logger = logging.getLogger(__name__)


# Default session TTL — 30 days. Kept as a module-level constant for backwards
# compatibility with downstream code and regression tests that import it.
# At runtime, prefer ``_resolve_session_ttl()`` which honours the env var and
# settings.json overrides; this constant is the floor / fallback.
SESSION_TTL = 86400 * 30  # 30 days


def _resolve_session_ttl() -> int:
    """Resolve session TTL from env > settings > default.

    Priority mirrors get_password_hash(): HERMES_WEBUI_SESSION_TTL env var
    first, then settings.json, falling back to ``SESSION_TTL`` (30 days).
    Clamped to [60s, 1 year] to prevent runaway cookies or self-lockout.
    """
    env_v = os.getenv('HERMES_WEBUI_SESSION_TTL', '').strip()
    if env_v.isdigit():
        val = int(env_v)
        if 60 <= val <= 86400 * 365:
            return val
    s = load_settings()
    v = s.get('session_ttl_seconds')
    if isinstance(v, int) and 60 <= v <= 86400 * 365:
        return v
    return SESSION_TTL


# ── Public paths (no auth required) ─────────────────────────────────────────
PUBLIC_PATHS = frozenset({
    '/login', '/health', '/favicon.ico', '/sw.js',
    '/api/auth/login', '/api/auth/status',
    '/api/auth/oidc/start', '/api/auth/oidc/callback',
    '/api/auth/passkey/options', '/api/auth/passkey/login',
    '/share',
    '/manifest.json', '/manifest.webmanifest',
    '/session/manifest.json', '/session/manifest.webmanifest',
})

COOKIE_NAME = 'hermes_session'
CSRF_HEADER_NAME = 'X-Hermes-CSRF-Token'


# RFC 6265 cookie-name token: a non-empty run of token chars
# (no controls, whitespace, or separators such as ';', '=', ',').
_COOKIE_NAME_RE = re.compile(r"^[-!#$%&'*+.^_`|~0-9A-Za-z]+$")


def _resolve_cookie_name() -> str:
    """Resolve the auth session cookie name from env > default.

    Honours ``HERMES_WEBUI_COOKIE_NAME`` so multiple WebUI instances sharing a
    hostname (different ports) can use distinct cookie names instead of
    trampling each other's session — browsers scope cookies by host, not
    host+port (RFC 6265). Falls back to ``COOKIE_NAME`` when the env var is
    unset, empty, or not a valid RFC 6265 token.
    """
    name = os.getenv('HERMES_WEBUI_COOKIE_NAME', '').strip()
    if not name:
        return COOKIE_NAME
    if _COOKIE_NAME_RE.match(name):
        return name
    logger.warning(
        'Ignoring invalid HERMES_WEBUI_COOKIE_NAME=%r; falling back to %r '
        '(name must be a valid RFC 6265 token)', name, COOKIE_NAME,
    )
    return COOKIE_NAME


def _warn_auth_persistence_failure(prefix: str, artifact: Path, exc: Exception, consequence: str) -> None:
    logger.warning(
        '%s at %s (STATE_DIR=%s): %s: %s; %s',
        prefix,
        artifact,
        STATE_DIR,
        exc.__class__.__name__,
        exc,
        consequence,
    )


_SESSIONS_FILE = STATE_DIR / '.sessions.json'
_TRUSTED_AUTH_HEADER_ENV = 'HERMES_WEBUI_TRUSTED_AUTH_HEADER'
_TRUSTED_GROUPS_HEADER_ENV = 'HERMES_WEBUI_TRUSTED_GROUPS_HEADER'
_TRUSTED_GROUP_PROFILE_MAP_ENV = 'HERMES_WEBUI_GROUP_PROFILE_MAP'
_TRUSTED_AUTH_LOGOUT_URL_ENV = 'HERMES_WEBUI_TRUSTED_AUTH_LOGOUT_URL'
_TRUSTED_AUTH_WARNINGS_EMITTED: set[str] = set()


def _warn_trusted_auth_once(key: str, message: str, *args) -> None:
    if key in _TRUSTED_AUTH_WARNINGS_EMITTED:
        return
    _TRUSTED_AUTH_WARNINGS_EMITTED.add(key)
    logger.warning(message, *args)


def _session_expiry(record) -> float | None:
    if isinstance(record, dict):
        expiry = record.get('expiry', record.get('expires_at'))
    else:
        expiry = record
    try:
        expiry_f = float(expiry)
    except (TypeError, ValueError):
        return None
    return expiry_f


def _load_sessions() -> dict[str, float | dict]:
    """Load persisted sessions from STATE_DIR, pruning expired entries.

    Returns an empty dict on any read or parse error so startup is never
    blocked by a corrupt or missing sessions file.
    """
    try:
        if not _SESSIONS_FILE.exists():
            return {}
        raw = _SESSIONS_FILE.read_text(encoding='utf-8')
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError('malformed sessions file: expected dict')
    except OSError as e:
        _warn_auth_persistence_failure(
            'Auth session store read failed',
            _SESSIONS_FILE,
            e,
            'starting fresh with an empty session table',
        )
        return {}
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        _warn_auth_persistence_failure(
            'Ignoring malformed auth session store',
            _SESSIONS_FILE,
            e,
            'starting fresh with an empty session table',
        )
        return {}
    except Exception as e:
        _warn_auth_persistence_failure(
            'Ignoring malformed auth session store',
            _SESSIONS_FILE,
            e,
            'starting fresh with an empty session table',
        )
        return {}
    now = time.time()
    sessions: dict[str, float | dict] = {}
    for token, record in data.items():
        if not isinstance(token, str) or not token:
            continue
        expiry = _session_expiry(record)
        if expiry is None or expiry <= now:
            continue
        if isinstance(record, dict):
            normalized = dict(record)
            normalized['expiry'] = expiry
            sessions[token] = normalized
        else:
            sessions[token] = expiry
    return sessions


def _save_sessions(sessions: dict[str, float | dict]) -> None:
    """Atomically persist sessions to STATE_DIR/.sessions.json (0600).

    Uses a temp file + os.replace() so a crash mid-write never leaves a
    truncated file.  Mirrors the same pattern as .signing_key persistence.
    """
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=STATE_DIR, suffix='.sessions.tmp')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(sessions, f)
            os.chmod(tmp, 0o600)
            os.replace(tmp, _SESSIONS_FILE)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except Exception as e:
        _warn_auth_persistence_failure(
            'Auth session persistence failed',
            _SESSIONS_FILE,
            e,
            'keeping the in-process session table available',
        )


# Active sessions: token -> expiry timestamp (persisted across restarts via STATE_DIR)
_sessions = _load_sessions()
_SESSIONS_LOCK = threading.Lock()

# ── Login rate limiter ──────────────────────────────────────────────────────
_LOGIN_ATTEMPTS_FILE = STATE_DIR / '.login_attempts.json'
_LOGIN_MAX_ATTEMPTS = 5
_LOGIN_WINDOW = 60  # seconds


def _load_login_attempts() -> dict[str, list[float]]:
    """Load persisted login attempts from STATE_DIR, pruning expired entries."""
    try:
        if _LOGIN_ATTEMPTS_FILE.exists():
            data = json.loads(_LOGIN_ATTEMPTS_FILE.read_text(encoding='utf-8'))
            if not isinstance(data, dict):
                raise ValueError('malformed login-attempts file — expected dict')
            now = time.time()
            attempts: dict[str, list[float]] = {}
            for ip, raw_times in data.items():
                if not isinstance(ip, str) or not isinstance(raw_times, list):
                    continue
                fresh = [
                    float(t)
                    for t in raw_times
                    if isinstance(t, (int, float)) and now - float(t) < _LOGIN_WINDOW
                ]
                if fresh:
                    attempts[ip] = fresh
            return attempts
    except Exception as e:
        logger.debug("Failed to load login attempts file, starting fresh: %s", e)
    return {}


def _save_login_attempts(attempts: dict[str, list[float]]) -> None:
    """Atomically persist login attempts to STATE_DIR/.login_attempts.json (0600)."""
    try:
        _LOGIN_ATTEMPTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=_LOGIN_ATTEMPTS_FILE.parent, suffix='.login_attempts.tmp')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(attempts, f)
            os.chmod(tmp, 0o600)
            os.replace(tmp, _LOGIN_ATTEMPTS_FILE)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except Exception as e:
        logger.debug("Failed to persist login attempts: %s", e)


_login_attempts = _load_login_attempts()  # ip -> [timestamp, ...]
_LOGIN_ATTEMPTS_LOCK = threading.Lock()


def _check_login_rate(ip: str) -> bool:
    """Return True if the IP is allowed to attempt login (thread-safe)."""
    with _LOGIN_ATTEMPTS_LOCK:
        now = time.time()
        attempts = _login_attempts.get(ip, [])
        # Prune old attempts
        attempts = [t for t in attempts if now - t < _LOGIN_WINDOW]
        if attempts:
            _login_attempts[ip] = attempts
        else:
            _login_attempts.pop(ip, None)
        _save_login_attempts(_login_attempts)
        return len(attempts) < _LOGIN_MAX_ATTEMPTS


def _record_login_attempt(ip: str) -> None:
    """Record a login attempt for rate limiting (thread-safe)."""
    with _LOGIN_ATTEMPTS_LOCK:
        now = time.time()
        attempts = _login_attempts.get(ip, [])
        attempts.append(now)
        _login_attempts[ip] = attempts
        _save_login_attempts(_login_attempts)


def _clear_login_attempts(ip: str) -> None:
    """Clear failed login attempts after a successful login (thread-safe)."""
    with _LOGIN_ATTEMPTS_LOCK:
        if ip in _login_attempts:
            _login_attempts.pop(ip, None)
            _save_login_attempts(_login_attempts)


def _load_key(filename: str) -> bytes:
    """Load a 32-byte key from STATE_DIR, generating and persisting one if missing."""
    key_file = STATE_DIR / filename
    try:
        if key_file.exists():
            raw = key_file.read_bytes()
            if len(raw) >= 32:
                return raw[:32]
    except OSError as e:
        _warn_auth_persistence_failure(
            'Auth key read failed',
            key_file,
            e,
            'generating a new key and continuing',
        )
    except Exception as e:
        _warn_auth_persistence_failure(
            'Auth key read failed',
            key_file,
            e,
            'generating a new key and continuing',
        )
    key = secrets.token_bytes(32)
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        key_file.write_bytes(key)
        key_file.chmod(0o600)
    except OSError as e:
        _warn_auth_persistence_failure(
            'Auth key persistence failed',
            key_file,
            e,
            'returning the generated key so startup can continue',
        )
    except Exception as e:
        _warn_auth_persistence_failure(
            'Auth key persistence failed',
            key_file,
            e,
            'returning the generated key so startup can continue',
        )
    return key


_PBKDF2_KEY_CACHE: bytes | None = None
_SIGNING_KEY_CACHE: bytes | None = None


def _pbkdf2_key() -> bytes:
    global _PBKDF2_KEY_CACHE
    if _PBKDF2_KEY_CACHE is None:
        _PBKDF2_KEY_CACHE = _load_key('.pbkdf2_key')
    return _PBKDF2_KEY_CACHE


def _signing_key() -> bytes:
    global _SIGNING_KEY_CACHE
    if _SIGNING_KEY_CACHE is None:
        _SIGNING_KEY_CACHE = _load_key('.signing_key')
    return _SIGNING_KEY_CACHE


def _hash_password(password, *, salt: bytes | None = None) -> str:
    """PBKDF2-SHA256 with 600k iterations (OWASP recommendation).
    Salt is the persisted PBKDF2 key, which is secret and unique per
    installation. This keeps the stored hash format a plain hex string
    (no format change to settings.json) while replacing the predictable
    STATE_DIR-derived salt from the original implementation.

    The *salt* parameter exists solely to support transparent migration
    of password hashes that were computed with a different key (e.g. the
    old `.signing_key`). Normal callers should never pass it.
    """
    if salt is None:
        salt = _pbkdf2_key()
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600_000)
    return dk.hex()


_AUTH_HASH_LOCK = threading.Lock()
_AUTH_HASH_COMPUTED: bool = False
_AUTH_HASH_CACHE: str | None = None


def _invalidate_password_hash_cache() -> None:
    """Invalidate the in-process password hash cache so the next call to
    get_password_hash() re-reads from settings.json or the env var."""
    global _AUTH_HASH_COMPUTED, _AUTH_HASH_CACHE
    with _AUTH_HASH_LOCK:
        _AUTH_HASH_COMPUTED = False
        _AUTH_HASH_CACHE = None


def get_password_hash() -> str | None:
    """Return the active password hash, or None if auth is disabled.
    Priority: env var > settings.json.

    The hash is computed once and cached for the lifetime of the process.
    PBKDF2-600k takes ~1 s and is called on nearly every HTTP request via
    check_auth → is_auth_enabled, so caching avoids wasting a full second
    of CPU per request after the first one.

    Thread-safe: double-checked locking ensures that under a burst of
    concurrent requests only one thread computes PBKDF2, while the fast
    path (after initialisation) requires zero locks.
    """
    global _AUTH_HASH_COMPUTED, _AUTH_HASH_CACHE

    # Fast path — no lock needed once cache is populated.
    if _AUTH_HASH_COMPUTED:
        return _AUTH_HASH_CACHE

    with _AUTH_HASH_LOCK:
        # Re-check inside lock — another thread may have populated while
        # we were waiting to acquire.
        if _AUTH_HASH_COMPUTED:
            return _AUTH_HASH_CACHE

        env_pw = os.getenv('HERMES_WEBUI_PASSWORD', '').strip()
        if env_pw:
            result = _hash_password(env_pw)
        else:
            result = load_settings().get('password_hash') or None

        _AUTH_HASH_CACHE = result
        _AUTH_HASH_COMPUTED = True
        return result


def is_password_auth_enabled() -> bool:
    """True if a password is configured (env var or settings)."""
    return get_password_hash() is not None


def _passkey_feature_flag_enabled() -> bool:
    """Return True if the passkey/WebAuthn surface is enabled for this deployment.

    Passkey support is opt-in default-off behind a feature flag so deployments
    that don't want the WebAuthn surface (or whose RP-ID setup isn't ready for
    non-localhost hosts) can disable it entirely with no UI surface, no
    endpoints, no credential storage. To enable:

      - Set ``HERMES_WEBUI_PASSKEY=1`` in the environment, OR
      - Set ``webui_passkey_enabled: true`` in the per-profile config.yaml

    With the flag off, ``are_passkeys_enabled()`` always returns False even if
    credentials were registered in the past, and ``/login`` shows password-only.
    """
    env_value = os.getenv("HERMES_WEBUI_PASSKEY", "")
    if env_value:
        return env_value.strip().lower() in {"1", "true", "yes", "on"}
    try:
        from api.config import get_config

        cfg = get_config()
        if isinstance(cfg, dict):
            raw = cfg.get("webui_passkey_enabled")
            if isinstance(raw, bool):
                return raw
            if isinstance(raw, str):
                return raw.strip().lower() in {"1", "true", "yes", "on"}
    except Exception:
        pass
    return False


def are_passkeys_enabled() -> bool:
    """True if the passkey feature flag is on AND at least one local passkey credential is registered."""
    if not _passkey_feature_flag_enabled():
        return False
    try:
        from api.passkeys import passkeys_available

        return passkeys_available()
    except Exception as exc:
        logger.debug("Failed to inspect passkey availability: %s", exc)
        return False


def is_oidc_auth_enabled() -> bool:
    """True if native OIDC login is configured for WebUI sessions."""
    try:
        from api.auth_oidc import is_oidc_enabled

        return is_oidc_enabled()
    except Exception as exc:
        logger.debug("Failed to inspect OIDC availability: %s", exc)
        return False


def get_oidc_startup_warning() -> str | None:
    """Return a startup warning when OIDC auth is only partially configured,
    or when allow_values uses whitespace that is no longer a separator."""
    try:
        cfg = get_config()
        raw = cfg.get("webui_oidc") if isinstance(cfg, dict) else {}
        if not isinstance(raw, dict):
            raw = {}
    except Exception:
        logger.debug("Failed to read webui_oidc config", exc_info=True)
        raw = {}

    def pick(name: str, env_name: str) -> str:
        env_value = os.getenv(env_name)
        value = env_value if env_value is not None else raw.get(name)
        return str(value or "").strip()

    issuer = bool(pick("issuer", "HERMES_WEBUI_OIDC_ISSUER"))
    client_id = bool(pick("client_id", "HERMES_WEBUI_OIDC_CLIENT_ID"))
    allow_claim = bool(pick("allow_claim", "HERMES_WEBUI_OIDC_ALLOW_CLAIM"))
    raw_allow_env = os.getenv("HERMES_WEBUI_OIDC_ALLOW_VALUES")
    raw_allow = raw_allow_env if raw_allow_env is not None else raw.get("allow_values")
    normalized_allow_values = []
    allow_values_warning = None
    try:
        from api import auth_oidc

        normalized_allow_values = auth_oidc._normalize_allow_values(raw_allow)
        allow_values_warning = auth_oidc._ALLOW_VALUES_WHITESPACE_WARNING
    except Exception:
        logger.debug("Failed to normalize OIDC allow_values", exc_info=True)
    allow_values = bool(normalized_allow_values)

    if not any((issuer, client_id, allow_claim, allow_values)):
        return None

    warnings = []

    if not (issuer and client_id and allow_claim and allow_values):
        missing = []
        if not issuer:
            missing.append("issuer")
        if not client_id:
            missing.append("client_id")
        if not allow_claim:
            missing.append("allow_claim")
        if not allow_values:
            missing.append("allow_values")
        joined = ", ".join(missing)
        warnings.append(
            "Native OIDC login is only partially configured; missing "
            f"{joined}. The WebUI will not enable OIDC auth until all four fields are set."
        )

    # Detect whitespace-only allow_values scalar that may contain multiple intended values.
    # Runs unconditionally so the warning reaches startup even when other auth methods
    # short-circuit is_auth_enabled() before the OIDC branch is evaluated.
    if (
        allow_values_warning is not None
        and raw_allow is not None
        and not isinstance(raw_allow, (list, tuple, set))
        and any(any(ch.isspace() for ch in v) for v in normalized_allow_values)
    ):
        warnings.append(allow_values_warning)

    return "\n".join(warnings) if warnings else None


def is_auth_enabled() -> bool:
    """True if password auth, passkeys, OIDC login, or trusted-header auth is configured."""
    return (
        is_password_auth_enabled()
        or are_passkeys_enabled()
        or is_oidc_auth_enabled()
        or is_trusted_auth_enabled()
    )


def verify_password(plain: str) -> bool:
    """Verify a plaintext password against the stored hash.

    Supports transparent migration of password hashes that were computed
    with the old `.signing_key` salt.  When the two keys differ and the
    legacy-salted hash matches, the password is transparently re-hashed
    with the current `.pbkdf2_key` and persisted to settings.json.
    """
    expected = get_password_hash()
    if not expected:
        return False
    # Fast path: current PBKDF2 key
    if hmac.compare_digest(_hash_password(plain), expected):
        return True
    # Migration: some hashes were computed with `.signing_key` before the
    # PBKDF2 key was separated.  Try the legacy salt; if it matches,
    # transparently upgrade so the next login uses the fast path.
    legacy_salt = _signing_key()
    current_salt = _pbkdf2_key()
    if legacy_salt != current_salt:
        if hmac.compare_digest(_hash_password(plain, salt=legacy_salt), expected):
            from api.config import save_settings

            save_settings({'_set_password': plain})
            # Password re-hashed and persisted to disk using the current salt.
            # Cache invalidation is handled by fix 2/3 (#2192) which adds the
            # _invalidate_password_hash_cache() call inside save_settings().
            return True
    return False


def create_session(*, auth_type: str | None = None, username: str | None = None, bound_profile: str | None = None) -> str:
    """Create a new auth session. Returns signed cookie value."""
    token = secrets.token_hex(32)
    expiry = time.time() + _resolve_session_ttl()
    record: float | dict
    if any(value is not None for value in (auth_type, username, bound_profile)):
        record = {
            'expiry': expiry,
            'auth_type': auth_type,
            'username': username,
            'bound_profile': bound_profile,
        }
    else:
        record = expiry
    with _SESSIONS_LOCK:
        _sessions[token] = record
        _save_sessions(_sessions)
    sig = hmac.new(_signing_key(), token.encode(), hashlib.sha256).hexdigest()
    return f"{token}.{sig}"


def _prune_expired_sessions():
    """Remove all expired session entries to prevent unbounded memory growth."""
    now = time.time()
    with _SESSIONS_LOCK:
        expired = [t for t, record in _sessions.items() if (expiry := _session_expiry(record)) is None or now > expiry]
        if expired:
            for token in expired:
                _sessions.pop(token, None)
            _save_sessions(_sessions)


def verify_session(cookie_value: str) -> bool:
    """Verify a signed session cookie. Returns True if valid and not expired."""
    if not cookie_value or '.' not in cookie_value:
        return False
    _prune_expired_sessions()  # lazy cleanup on every verification attempt
    token, sig = cookie_value.rsplit('.', 1)
    full_sig = hmac.new(_signing_key(), token.encode(), hashlib.sha256).hexdigest()
    # Accept both new (64-char) and legacy (32-char truncated) signatures so
    # existing sessions survive the upgrade without a forced global logout.
    # The legacy branch can be removed once session TTLs have expired (~30 days).
    valid = hmac.compare_digest(sig, full_sig) or (
        len(sig) == 32 and hmac.compare_digest(sig, full_sig[:32])
    )
    if not valid:
        return False
    with _SESSIONS_LOCK:
        expiry = _session_expiry(_sessions.get(token))
        if expiry is None or time.time() > expiry:
            _sessions.pop(token, None)
            _save_sessions(_sessions)
            return False
    return True


def _trusted_auth_header_name() -> str | None:
    name = os.getenv(_TRUSTED_AUTH_HEADER_ENV, '').strip()
    if not name:
        return None
    if not _COOKIE_NAME_RE.match(name):
        _warn_trusted_auth_once(
            'trusted-auth-header',
            'Ignoring invalid %s=%r; trusted-header auth rejects every request',
            _TRUSTED_AUTH_HEADER_ENV,
            name,
        )
        return None
    return name


def _trusted_auth_header_configured() -> bool:
    return bool(os.getenv(_TRUSTED_AUTH_HEADER_ENV, '').strip())


def _trusted_group_profile_map() -> dict[str, str] | None:
    raw = os.getenv(_TRUSTED_GROUP_PROFILE_MAP_ENV, '').strip()
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        _warn_trusted_auth_once(
            'trusted-group-map',
            'Ignoring invalid %s JSON; trusted-header auth falls back to default profile binding',
            _TRUSTED_GROUP_PROFILE_MAP_ENV,
        )
        return {}
    if not isinstance(data, dict):
        _warn_trusted_auth_once(
            'trusted-group-map-type',
            'Ignoring non-dict %s; trusted-header auth falls back to default profile binding',
            _TRUSTED_GROUP_PROFILE_MAP_ENV,
        )
        return {}
    mapping: dict[str, str] = {}
    for group, profile in data.items():
        group_name = str(group or '').strip()
        profile_name = str(profile or '').strip()
        if not group_name or not profile_name:
            _warn_trusted_auth_once(
                'trusted-group-map-entry',
                'Ignoring invalid entry in %s; trusted-header auth falls back to default profile binding',
                _TRUSTED_GROUP_PROFILE_MAP_ENV,
            )
            continue
        mapping[group_name] = profile_name
    return mapping


def _trusted_groups_header_value(handler) -> list[str]:
    header_name = os.getenv(_TRUSTED_GROUPS_HEADER_ENV, '').strip()
    if not header_name:
        return []
    try:
        raw = handler.headers.get(header_name, '')
    except Exception:
        return []
    if not raw:
        return []
    values = []
    for part in str(raw).replace('\n', ',').split(','):
        part = part.strip()
        if part:
            values.append(part)
    return values


def _trusted_auth_username(handler) -> str | None:
    header_name = _trusted_auth_header_name()
    if not header_name:
        return None
    try:
        raw = handler.headers.get(header_name, '')
    except Exception:
        return None
    username = str(raw or '').strip()
    return username or None


def _trusted_auth_bound_profile(handler) -> str | None:
    mapping = _trusted_group_profile_map()
    if mapping is None:
        return None
    groups = set(_trusted_groups_header_value(handler))
    for group, profile in mapping.items():
        if group in groups:
            return profile
    return 'default'


def _queue_pending_cookie(handler, cookie_header: str) -> None:
    if not cookie_header:
        return
    pending = getattr(handler, '_pending_set_cookies', None)
    if pending is None:
        pending = []
        handler._pending_set_cookies = pending
    pending.append(cookie_header)


def _auth_cookie_header(cookie_value, handler=None) -> str:
    cookie = http.cookies.SimpleCookie()
    name = _resolve_cookie_name()
    cookie[name] = cookie_value
    cookie[name]['httponly'] = True
    cookie[name]['samesite'] = 'Lax'
    cookie[name]['path'] = '/'
    cookie[name]['max-age'] = str(_resolve_session_ttl())
    if _is_secure_context(handler):
        cookie[name]['secure'] = True
    return cookie[name].OutputString()


def _clear_auth_cookie_header() -> str:
    cookie = http.cookies.SimpleCookie()
    name = _resolve_cookie_name()
    cookie[name] = ''
    cookie[name]['httponly'] = True
    cookie[name]['path'] = '/'
    cookie[name]['samesite'] = 'Lax'
    cookie[name]['max-age'] = '0'
    return cookie[name].OutputString()


def _build_profile_cookie_header(name: str, session_cookie_value: str | None) -> str:
    from api.helpers import build_profile_cookie

    return build_profile_cookie(name, session_cookie_value=session_cookie_value)


def _request_profile_matches_bound(bound_profile: str | None) -> bool:
    if not bound_profile:
        return True
    try:
        from api.profiles import get_active_profile_name, _profiles_match

        return _profiles_match(bound_profile, get_active_profile_name())
    except Exception:
        return False


def get_session_info(cookie_value: str) -> dict | None:
    if not verify_session(cookie_value):
        return None
    token = _session_token_from_cookie_value(cookie_value)
    if not token:
        return None
    with _SESSIONS_LOCK:
        record = _sessions.get(token)
    expiry = _session_expiry(record)
    if expiry is None:
        return None
    info: dict[str, object] = {'token': token, 'expiry': expiry}
    if isinstance(record, dict):
        info.update({k: v for k, v in record.items() if k != 'expiry'})
    if 'bound_profile' not in info and isinstance(info.get('profile'), str):
        info['bound_profile'] = info.get('profile')
    info.setdefault('auth_type', None)
    info.setdefault('username', None)
    info.setdefault('bound_profile', None)
    return info


def session_bound_profile(cookie_value: str) -> str | None:
    info = get_session_info(cookie_value)
    if not info:
        return None
    bound_profile = info.get('bound_profile')
    bound_profile = str(bound_profile or '').strip()
    return bound_profile or None


def is_trusted_auth_enabled() -> bool:
    return _trusted_auth_header_configured()


def get_trusted_auth_logout_url() -> str | None:
    value = os.getenv(_TRUSTED_AUTH_LOGOUT_URL_ENV, '').strip()
    return value or None


def _remember_trusted_auth_session(handler, info: dict | None, cookie_value: str | None = None) -> dict | None:
    handler._trusted_auth_session_reconciled = info
    if info and info.get('auth_type') == 'trusted':
        handler._trusted_auth_session_info = info
        handler._trusted_auth_session_cookie_value = cookie_value
    return info


def reset_trusted_auth_request_state(handler) -> None:
    for name in (
        '_trusted_auth_session_reconciled',
        '_trusted_auth_session_rejected',
        '_trusted_auth_session_info',
        '_trusted_auth_session_cookie_value',
        # Clear any auth cookie queued by a prior request but not yet flushed.
        # The handler is reused across HTTP/1.1 keep-alive requests, so a stale
        # queued Set-Cookie would otherwise cross the request boundary and be
        # emitted by a later response — e.g. after trusted-identity rotation on
        # logout it could overwrite a subsequent valid login cookie and 401 the
        # user. Reset it at the per-request boundary (server.py do_GET/do_POST).
        '_pending_set_cookies',
    ):
        try:
            delattr(handler, name)
        except AttributeError:
            pass


def _apply_trusted_session_profile(handler, bound_profile: str | None, cookie_value: str) -> None:
    if bound_profile is None:
        return
    from api.helpers import get_profile_cookie
    from api.profiles import set_request_profile

    set_request_profile(bound_profile)
    if get_profile_cookie(handler) != bound_profile:
        _queue_pending_cookie(handler, _build_profile_cookie_header(bound_profile, cookie_value))


def ensure_trusted_auth_session(handler) -> dict | None:
    if hasattr(handler, '_trusted_auth_session_reconciled'):
        return handler._trusted_auth_session_reconciled
    cookie_value = parse_cookie(handler)
    info = get_session_info(cookie_value) if cookie_value and verify_session(cookie_value) else None
    if info and info.get('auth_type') != 'trusted':
        return _remember_trusted_auth_session(handler, info)
    if not is_trusted_auth_enabled():
        if info:
            invalidate_session(cookie_value)
            handler._trusted_auth_session_rejected = True
        return _remember_trusted_auth_session(handler, None)
    from api.routes import _raw_peer_is_trusted_proxy

    if not _raw_peer_is_trusted_proxy(handler):
        if info:
            invalidate_session(cookie_value)
            handler._trusted_auth_session_rejected = True
        return _remember_trusted_auth_session(handler, None)
    username = _trusted_auth_username(handler)
    if not username:
        if info:
            invalidate_session(cookie_value)
            handler._trusted_auth_session_rejected = True
        return _remember_trusted_auth_session(handler, None)
    bound_profile = _trusted_auth_bound_profile(handler)
    if info and info.get('username') == username and info.get('bound_profile') == bound_profile:
        _apply_trusted_session_profile(handler, bound_profile, cookie_value)
        return _remember_trusted_auth_session(handler, info, cookie_value)
    if info:
        invalidate_session(cookie_value)
    cookie_value = create_session(
        auth_type='trusted',
        username=username,
        bound_profile=bound_profile,
    )
    _queue_pending_cookie(handler, _auth_cookie_header(cookie_value, handler))
    _apply_trusted_session_profile(handler, bound_profile, cookie_value)
    info = get_session_info(cookie_value)
    return _remember_trusted_auth_session(handler, info, cookie_value)


def trusted_session_allows_active_profile(info: dict | None) -> bool:
    if not info:
        return True
    return _request_profile_matches_bound(str(info.get('bound_profile') or '') or None)


def _session_token_from_cookie_value(cookie_value: str) -> str | None:
    """Return the raw server-side session token from a signed cookie value."""
    if not cookie_value or '.' not in cookie_value:
        return None
    token, _sig = cookie_value.rsplit('.', 1)
    return token or None


def sign_profile_cookie_value(profile_name: str, session_cookie_value: str | None) -> str:
    """Return a profile cookie value authenticated for one WebUI session.

    The active-profile cookie is client-controlled, so when auth is enabled it
    must not be trusted as a bare profile name. Binding the selected profile to
    the HttpOnly session token prevents a client from forging
    ``hermes_profile=<other-profile>`` and bypassing profile visibility guards.
    """
    if not session_cookie_value or not verify_session(session_cookie_value):
        raise ValueError("active auth session is required to sign profile cookie")
    token = _session_token_from_cookie_value(session_cookie_value)
    if not token:
        raise ValueError("active auth session is required to sign profile cookie")
    sig = hmac.new(
        _signing_key(),
        f"profile:{token}:{profile_name}".encode(),
        hashlib.sha256,
    ).hexdigest()
    return f"{profile_name}.{sig}"


def verify_profile_cookie_value(cookie_value: str, session_cookie_value: str | None) -> str | None:
    """Verify a session-bound profile cookie and return its profile name."""
    if not cookie_value or '.' not in cookie_value:
        return None
    if not session_cookie_value or not verify_session(session_cookie_value):
        return None
    profile_name, sig = cookie_value.rsplit('.', 1)
    token = _session_token_from_cookie_value(session_cookie_value)
    if not profile_name or not token or not sig:
        return None
    # Defense-in-depth: validate the profile-name pattern here too, not only in
    # get_profile_cookie(), so any future caller of this verifier can't return an
    # unvalidated name. (#4023 Opus hardening.)
    from api.profiles import _PROFILE_ID_RE
    if profile_name != 'default' and not _PROFILE_ID_RE.fullmatch(profile_name):
        return None
    expected = hmac.new(
        _signing_key(),
        f"profile:{token}:{profile_name}".encode(),
        hashlib.sha256,
    ).hexdigest()
    if hmac.compare_digest(str(sig), expected):
        return profile_name
    return None


def csrf_token_for_session(cookie_value: str) -> str | None:
    """Return the CSRF token bound to an authenticated WebUI session.

    The browser can read this token from the authenticated shell and echoes it
    in ``X-Hermes-CSRF-Token`` on unsafe API requests. The token is derived
    from the HttpOnly session cookie's server-side token, so it automatically
    rotates on login and is invalidated when the auth session expires or logs
    out. Callers must still verify the auth session before trusting it.
    """
    token = _session_token_from_cookie_value(cookie_value)
    if not token:
        return None
    return hmac.new(_signing_key(), f"csrf:{token}".encode(), hashlib.sha256).hexdigest()


def verify_csrf_token(cookie_value: str, csrf_token: str) -> bool:
    """Verify a submitted CSRF token against the authenticated session."""
    if not cookie_value or not csrf_token or not verify_session(cookie_value):
        return False
    expected = csrf_token_for_session(cookie_value)
    return bool(expected and hmac.compare_digest(str(csrf_token), expected))


def invalidate_session(cookie_value) -> None:
    """Remove a session token."""
    if cookie_value and '.' in cookie_value:
        token = cookie_value.rsplit('.', 1)[0]
        with _SESSIONS_LOCK:
            if token in _sessions:
                _sessions.pop(token, None)
                _save_sessions(_sessions)


def parse_cookie(handler) -> str | None:
    """Extract the auth cookie from the request headers."""
    cookie_header = handler.headers.get('Cookie', '')
    if not cookie_header:
        return None
    cookie = http.cookies.SimpleCookie()
    try:
        cookie.load(cookie_header)
    except http.cookies.CookieError:
        return None
    morsel = cookie.get(_resolve_cookie_name())
    return morsel.value if morsel else None


def _safe_login_inner_next(query: str | None) -> str:
    """#5578: extract a SAFE, non-login inner redirect from a login page's query.

    When an expired-auth bounce lands back on the login page (which already
    carries its own `next` in the query), we want to preserve a legitimate inner
    destination X across the redirect to the real login route — but only if X is
    itself safe (path-absolute, not protocol-relative/backslash, no control
    chars) AND not login-shaped / not itself carrying a nested next param.
    Anything else collapses to '' (no inner redirect), which kills the
    self-referential chain. Mirrors _safe_login_redirect_path().
    """
    import urllib.parse as _u
    raw = _u.parse_qs(query or "").get("next", [""])[0]
    path = str(raw or "").strip()
    if not path or path[0] != "/" or path[1:2] in {"/", "\\"}:
        return ""
    if re.search(r"[\x00-\x1f\x7f\s]", path) or len(path) > 2048:
        return ""
    # Collapse only login-route chains — decode a few levels so a nested
    # `/session/login%3Fnext%3D...` (encoded `?`) is still recognized by its
    # leading PATH — but preserve a legitimate non-login inner path that merely
    # carries its own `next=` query key (e.g. `/admin?next=/real/path`).
    _probe = path
    for _ in range(8):
        _p = _probe.split("?", 1)[0].split("#", 1)[0].split("&", 1)[0].rstrip("/")
        if _p == "/login" or _p.endswith("/login"):
            return ""
        _decoded = _u.unquote(_probe)
        if _decoded == _probe:
            break
        _probe = _decoded
    else:
        # Still decoding at the cap (pathologically deep encoding) → fail closed.
        _p = _probe.split("?", 1)[0].split("#", 1)[0].split("&", 1)[0].rstrip("/")
        if _p == "/login" or _p.endswith("/login"):
            return ""
        return ""
    return path


def check_auth(handler, parsed) -> bool:
    """Check if request is authorized. Returns True if OK.
    If not authorized, sends 401 (API) or 302 redirect (page) and returns False."""
    if not is_auth_enabled():
        return True
    # Public paths don't require auth
    if (
        parsed.path in PUBLIC_PATHS
        or parsed.path.startswith('/share/')
        or (
            parsed.path.startswith('/api/share/')
            and parsed.path not in {'/api/share/create', '/api/share/revoke'}
        )
        or parsed.path.startswith('/static/')
        or parsed.path.startswith('/session/static/')
    ):
        return True
    cookie_val = parse_cookie(handler)
    has_session = bool(cookie_val and verify_session(cookie_val))
    if parsed.path == '/api/auth/logout':
        if has_session:
            return True
        body = b'{"error":"Authentication required"}'
        handler.send_response(401)
        handler.send_header('Content-Type', 'application/json')
        handler.send_header('Content-Length', str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)
        return False
    session_info = ensure_trusted_auth_session(handler)
    if session_info:
        if not trusted_session_allows_active_profile(session_info):
            if parsed.path.startswith('/api/'):
                body = b'{"error":"Profile access forbidden"}'
                handler.send_response(403)
                handler.send_header('Content-Type', 'application/json')
            else:
                body = b'Profile access forbidden'
                handler.send_response(403)
                handler.send_header('Content-Type', 'text/plain; charset=utf-8')
            handler.send_header('Content-Length', str(len(body)))
            handler.end_headers()
            handler.wfile.write(body)
            return False
        return True
    # Not authorized
    if parsed.path.startswith('/api/'):
        body = b'{"error":"Authentication required"}'
        handler.send_response(401)
        handler.send_header('Content-Type', 'application/json')
        handler.send_header('Content-Length', str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)
    else:
        handler.send_response(302)
        # Pass the original path as ?next= so login.js redirects back after auth.
        # SECURITY/CORRECTNESS: the inner `?` and `&` MUST be percent-encoded
        # when stuffed into the outer `?next=` parameter, otherwise:
        #   (a) multi-param query strings get truncated at the first inner `&`
        #       (e.g. `/api/sessions?limit=50&offset=0` would round-trip as
        #       just `/api/sessions?limit=50` after the browser parses the
        #       outer URL — `offset=0` becomes a separate top-level query
        #       parameter that the login page ignores).
        #   (b) attacker-controlled paths could inject a second `next=`
        #       parameter; per RFC 3986 the duplicate behaviour is undefined
        #       and parsers diverge (Python's parse_qs returns last-match,
        #       URLSearchParams returns first-match), opening a query-pollution
        #       footgun even though _safeNextPath() rejects most malicious
        #       shapes downstream.
        # Encoding the entire `path?query` blob with quote(safe='/') turns
        # `?` → `%3F` and `&` → `%26`, so the outer parameter holds exactly
        # one path-with-query string and `searchParams.get('next')` returns
        # the full original URL (the browser auto-decodes once).
        # (Opus pre-release advisor finding for v0.50.258.)
        import urllib.parse as _urlparse
        # #5578: if the page being redirected is ALREADY login-shaped, do NOT
        # wrap its full `path?query` into a fresh `next=` — that query already
        # carries a `next=`, so quoting the whole thing nests the login URL into
        # itself and re-encodes it on every expired-auth bounce, exploding the
        # URL until the tab breaks. This guard runs in check_auth() (BEFORE
        # route handling), the actual source of the server-side loop.
        #
        # The login page is served ONLY at the public `/login` route (see
        # PUBLIC_PATHS + the routes.py `/login` handler); the app's client route
        # `/session/login` is NOT public, so a bare relative `login` from
        # `/session/login` resolves to `/session/login` again and re-triggers
        # check_auth() — an infinite redirect. Resolve to the real login route
        # with `../login`, which lands on `/login` from a `/session/*` scope and
        # on `<mount>/login` under a subpath mount (verified via urljoin). Carry
        # through only a validated, non-login inner `next` so a legitimate
        # post-login destination still survives a bounce that happened to land
        # on the login page.
        _login_path = (parsed.path or '/').rstrip('/')
        if _login_path == '/login' or _login_path.endswith('/login'):
            # /login itself is public → check_auth never redirects it; this only
            # fires for the non-public client login route (e.g. /session/login).
            _target = '../login' if '/' in _login_path.lstrip('/') else 'login'
            _inner = _safe_login_inner_next(parsed.query)
            if _inner:
                _target += '?next=' + _urlparse.quote(_inner, safe='/')
            handler.send_header('Location', _target)
            handler.send_header('Content-Length', '0')
            handler.end_headers()
            return False
        _path_with_query = parsed.path or '/'
        if parsed.query:
            _path_with_query += '?' + parsed.query
        # safe='/' keeps path separators readable; everything else (including
        # `?`, `&`, `=`) gets percent-encoded.
        _next = _urlparse.quote(_path_with_query, safe='/')
        handler.send_header('Location', 'login?next=' + _next)
        handler.send_header('Content-Length', '0')
        handler.end_headers()
    return False


def _is_loopback(addr: str) -> bool:
    """Return True if *addr* is a loopback address (127.x.x.x, ::1, or ::ffff:127.x.x.x)."""
    import ipaddress as _ipaddress
    try:
        ip = _ipaddress.ip_address(addr)
        if ip.is_loopback:
            return True
        # Python < 3.12: is_loopback is False for ::ffff:127.x.x.x (gh-117566)
        if hasattr(ip, 'ipv4_mapped') and ip.ipv4_mapped is not None:
            return ip.ipv4_mapped.is_loopback
        return False
    except ValueError:
        return False


def _is_secure_context(handler=None) -> bool:
    """Return True if cookies should carry the Secure flag.

    Priority order:
    1. ``HERMES_WEBUI_SECURE`` env var: 1/true/yes -> True; 0/false/no -> False.
    2. Direct TLS socket (handler.request.getpeercert present) -> True.
    3. ``HERMES_WEBUI_TRUST_FORWARDED_PROTO=1`` opt-in: trust
       ``X-Forwarded-Proto: https`` header from a known reverse proxy.
    4. Otherwise -> False (loopback or non-loopback, plain HTTP is not secure).

    .. warning::
       ``X-Forwarded-Proto`` is only trustworthy behind a reverse proxy.
       It is ignored unless ``HERMES_WEBUI_TRUST_FORWARDED_PROTO=1`` is
       set explicitly, preventing header-injection attacks on plain-HTTP
       deployments.
    """
    env = os.getenv('HERMES_WEBUI_SECURE', '').strip().lower()
    if env in ('1', 'true', 'yes'):
        return True
    if env in ('0', 'false', 'no'):
        return False
    if handler is not None:
        if getattr(handler.request, 'getpeercert', None) is not None:
            return True
        trust_fwd = os.getenv('HERMES_WEBUI_TRUST_FORWARDED_PROTO', '').strip().lower()
        if trust_fwd in ('1', 'true', 'yes'):
            if handler.headers.get('X-Forwarded-Proto', '') == 'https':
                return True
    return False


def set_auth_cookie(handler, cookie_value) -> None:
    """Set the auth cookie on the response."""
    handler.send_header('Set-Cookie', _auth_cookie_header(cookie_value, handler))


def clear_auth_cookie(handler) -> None:
    """Clear the auth cookie on the response."""
    handler.send_header('Set-Cookie', _clear_auth_cookie_header())


# ─────────────────────────────────────────────────────────────────────────────
# Read-only raw-memory seams (hermex #58, PR 0) — contract §5 / §7 / §8
#
# These seams are PURE and DETACHED: they read the authoritative on-disk state
# directly (environment, STATE_DIR/settings.json, profile config.yaml files,
# STATE_DIR/.signing_key, STATE_DIR/.sessions.json, STATE_DIR/passkeys.json)
# with bounded no-follow regular-file semantics and never mutate any state —
# no key generation, no session mint/prune/persist/refresh/revoke, no cookie
# queueing, no discovery/alias caches, no directory creation, no
# profile-registry refresh, no request-profile TLS mutation, and no
# consultation of the process active profile. They exist for PR 0 only; the
# raw route (PR 2) consumes them. PR 0 adds no route, no dispatch, and no
# capability field.
# ─────────────────────────────────────────────────────────────────────────────

# Tri-state results of read_only_auth_enabled() (§7).
AUTH_ENABLED = 'auth_enabled'
AUTH_DISABLED = 'auth_disabled'
AUTH_STATE_UNAVAILABLE = 'auth_state_unavailable'

# Per-member posture results (internal).
_READ_ONLY_ENABLED = 'enabled'
_READ_ONLY_DISABLED = 'disabled'
_READ_ONLY_UNAVAILABLE = 'unavailable'

# Per-config-file read outcomes (internal).
_CFG_MISSING = 'missing'
_CFG_OK = 'ok'
_CFG_UNREADABLE = 'unreadable'

# Bounded-read caps for the no-follow regular-file reader. Oversized files
# fail closed (treated as unreadable) rather than being partially trusted.
_READ_ONLY_MAX_SETTINGS_BYTES = 4 * 1024 * 1024
_READ_ONLY_MAX_CONFIG_BYTES = 4 * 1024 * 1024
_READ_ONLY_MAX_SESSIONS_BYTES = 8 * 1024 * 1024
_READ_ONLY_MAX_PASSKEYS_BYTES = 4 * 1024 * 1024
_READ_ONLY_MAX_SIGNING_KEY_BYTES = 4096


@dataclass(frozen=True)
class AuthorizedRawProfileContext:
    """The single immutable per-request authorization context (§5 of #58).

    Carries only the normalized bound profile name, the resolved absolute
    Profile home ``Path``, the validated incoming session identifier, and an
    optional read-only view of the validated session record. It must never
    carry cookie values, keys, or raw source bytes. It is never stored in a
    module global, thread-local, or process-TLS slot; it lives only on the raw
    request's call stack and is passed by parameter into every pure resolver.
    """

    bound_profile: str
    profile_home: Path
    auth_session_id: str
    session_record_view: Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.bound_profile, str) or not self.bound_profile.strip():
            raise ValueError('bound_profile must be a non-empty profile name')
        if not isinstance(self.auth_session_id, str) or not self.auth_session_id.strip():
            raise ValueError('auth_session_id must be a non-empty session identifier')
        if not isinstance(self.profile_home, Path):
            raise ValueError('profile_home must be a Path')
        object.__setattr__(self, 'bound_profile', self.bound_profile.strip())
        object.__setattr__(self, 'auth_session_id', self.auth_session_id.strip())
        object.__setattr__(self, 'profile_home', self.profile_home.expanduser().resolve())


def _read_regular_file_no_follow(path: Path, max_bytes: int) -> bytes | None:
    """Read a regular file with bounded, no-follow semantics.

    Returns the file bytes (``len <= max_bytes``) or ``None`` when the path is
    missing, is not a regular file (symlink, directory, FIFO, device), cannot
    be opened, is replaced/rotated between stat and read, or exceeds the
    bound. Pre/post identity checks compare ``(st_dev, st_ino)`` against the
    initial lstat so a concurrent replacement fails closed. Never creates,
    writes, or repairs anything.
    """
    try:
        st_before = path.lstat()
    except OSError:
        return None
    if not stat.S_ISREG(st_before.st_mode):
        return None
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        st_fd = os.fstat(fd)
        if not stat.S_ISREG(st_fd.st_mode):
            return None
        if (st_fd.st_dev, st_fd.st_ino) != (st_before.st_dev, st_before.st_ino):
            return None
        chunks = []
        total = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                return None
            chunks.append(chunk)
        st_after = os.fstat(fd)
        if (st_after.st_dev, st_after.st_ino) != (st_before.st_dev, st_before.st_ino):
            return None
        return b''.join(chunks)
    except OSError:
        return None
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def _read_only_signing_key() -> bytes | None:
    """Direct no-follow read of the authoritative ``STATE_DIR/.signing_key``.

    Preserves the existing 32-byte / first-32-byte compatibility rule. A
    missing, short, symlinked, unreadable, or otherwise invalid key fails
    closed (``None``) and never generates or writes a replacement. The key is
    authoritative per call: no raw-route key cache or stale in-memory
    fallback is permitted.
    """
    raw = _read_regular_file_no_follow(
        STATE_DIR / '.signing_key', _READ_ONLY_MAX_SIGNING_KEY_BYTES
    )
    if raw is None or len(raw) < 32:
        return None
    return raw[:32]


def _read_only_session_expiry(record) -> float | None:
    """Mirror of ``_session_expiry()`` kept inside the seam for detachment."""
    if isinstance(record, dict):
        expiry = record.get('expiry', record.get('expires_at'))
    else:
        expiry = record
    try:
        return float(expiry)
    except (TypeError, ValueError):
        return None


def _read_only_sessions_store() -> dict | None:
    """Direct no-follow read of ``STATE_DIR/.sessions.json``.

    Never calls ``_load_sessions()`` (which prunes and persists) or
    ``_save_sessions()``. A missing, unreadable, malformed, non-dict, or
    replaced store returns ``None`` (fail closed) without pruning, persisting,
    refreshing, or mutating the in-process ``_sessions`` table.
    """
    raw = _read_regular_file_no_follow(
        STATE_DIR / '.sessions.json', _READ_ONLY_MAX_SESSIONS_BYTES
    )
    if raw is None:
        return None
    try:
        data = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def read_only_incoming_cookie_session_info(cookie_value: str) -> dict | None:
    """Validate the exact incoming auth cookie (§8).

    Reads the exact incoming cookie value against ONE direct signing-key
    snapshot and ONE direct on-disk ``STATE_DIR/.sessions.json`` snapshot.
    Accepts the current 64-character signature and the accepted legacy
    32-character truncated form. Checks expiry. Returns a detached bound-session
    info record ``{'token', 'expiry', 'auth_type', 'username',
    'bound_profile'}`` or ``None``.

    Never calls ``_prune_expired_sessions()``, removes an expired record,
    persists the session store, refreshes/rotates a session, mints a cookie,
    queues or flushes ``Set-Cookie``, populates or invalidates an
    auth/session/key cache, or performs any other state mutation. Never calls
    the mutating ``verify_session()`` or ``get_session_info()``.
    """
    if not cookie_value or '.' not in cookie_value:
        return None
    token, sig = cookie_value.rsplit('.', 1)
    if not token or not sig:
        return None
    key = _read_only_signing_key()
    if key is None:
        return None
    full_sig = hmac.new(key, token.encode(), hashlib.sha256).hexdigest()
    valid = hmac.compare_digest(sig, full_sig) or (
        len(sig) == 32 and hmac.compare_digest(sig, full_sig[:32])
    )
    if not valid:
        return None
    with _SESSIONS_LOCK:
        data = _read_only_sessions_store()
    if data is None:
        return None
    record = data.get(token)
    if record is None:
        return None
    expiry = _read_only_session_expiry(record)
    if expiry is None or time.time() > expiry:
        return None
    info: dict[str, object] = {'token': token, 'expiry': expiry}
    if isinstance(record, dict):
        info.update({k: v for k, v in record.items() if k != 'expiry'})
    if 'bound_profile' not in info and isinstance(info.get('profile'), str):
        info['bound_profile'] = info.get('profile')
    info.setdefault('auth_type', None)
    info.setdefault('username', None)
    info.setdefault('bound_profile', None)
    return info


def read_only_verify_profile_cookie(
    cookie_value: str, session_cookie_value: str | None
) -> str | None:
    """Pure companion seam for signed profile-cookie verification (§8).

    Uses the same token/HMAC input as ``sign_profile_cookie_value()``
    (HMAC-SHA256 over ``b'profile:<token>:<name>'`` with the direct signing
    key) and returns a detached comparison result only. It must not call
    ``get_profile_cookie()``, ``get_profile_cookie_name()``, ``parse_cookie()``,
    ``verify_profile_cookie_value()``, ``verify_session()``,
    ``get_session_info()``, or any helper that can generate a key,
    prune/persist sessions, queue cookies, populate alias/discovery caches,
    warning-once state, or switch the process-global Profile. This seam
    performs no TLS profile mutation of any kind.
    """
    if not cookie_value or '.' not in cookie_value:
        return None
    if not session_cookie_value or '.' not in session_cookie_value:
        return None
    profile_name, sig = cookie_value.rsplit('.', 1)
    token, _session_sig = session_cookie_value.rsplit('.', 1)
    if not profile_name or not sig or not token:
        return None
    from api.profiles import _PROFILE_ID_RE

    if profile_name != 'default' and not _PROFILE_ID_RE.fullmatch(profile_name):
        return None
    key = _read_only_signing_key()
    if key is None:
        return None
    expected = hmac.new(
        key, f'profile:{token}:{profile_name}'.encode(), hashlib.sha256
    ).hexdigest()
    if hmac.compare_digest(str(sig), expected):
        return profile_name
    return None


def _read_only_profiles_root() -> Path:
    """Canonical profile registry root (base home / ``profiles``).

    Mirrors ``api.profiles._profiles_root()`` without touching any profile
    registry cache, alias cache, or refresh path.
    """
    from api import profiles as _profiles

    return (Path(_profiles._DEFAULT_HERMES_HOME) / 'profiles').resolve()


def _read_only_profile_scopes() -> list[tuple[str, Path]]:
    """Direct enumeration of profile homes under the registry root (§7).

    The root profile scope is the base home itself; every immediate child of
    the registry root that is a real directory (lstat, no symlink following)
    is a named-profile scope. No discovery caches, no alias caches, no
    ``_profiles_match()`` alias population, no directory creation, no
    migration, and no profile-registry refresh. A missing registry root
    contributes no named scopes.
    """
    from api import profiles as _profiles

    base = Path(_profiles._DEFAULT_HERMES_HOME)
    scopes: list[tuple[str, Path]] = [('default', base)]
    try:
        entries = sorted(_read_only_profiles_root().iterdir())
    except OSError:
        entries = []
    for entry in entries:
        try:
            if stat.S_ISDIR(entry.lstat().st_mode):
                scopes.append((entry.name, entry))
        except OSError:
            continue
    return scopes


def _read_only_profile_config(home: Path) -> tuple[str, dict]:
    """Read one profile home's ``config.yaml`` with bounded no-follow reads.

    Returns ``(_CFG_MISSING, {})`` when the file is absent (readable, no
    posture), ``(_CFG_OK, cfg)`` for a valid YAML mapping, or
    ``(_CFG_UNREADABLE, {})`` for symlink/non-regular/oversized/unreadable/
    malformed/non-mapping state (fail closed).
    """
    path = home / 'config.yaml'
    try:
        st = path.lstat()
    except FileNotFoundError:
        return _CFG_MISSING, {}
    except OSError:
        return _CFG_UNREADABLE, {}
    if not stat.S_ISREG(st.st_mode):
        return _CFG_UNREADABLE, {}
    raw = _read_regular_file_no_follow(path, _READ_ONLY_MAX_CONFIG_BYTES)
    if raw is None:
        return _CFG_UNREADABLE, {}
    try:
        import yaml

        loaded = yaml.safe_load(raw.decode('utf-8'))
    except Exception:
        return _CFG_UNREADABLE, {}
    if loaded is None:
        return _CFG_OK, {}
    if not isinstance(loaded, dict):
        return _CFG_UNREADABLE, {}
    return _CFG_OK, loaded


def _read_only_bool_string(value: str) -> bool | None:
    """Parse a passkey flag string; ``None`` means malformed (fail closed)."""
    normalized = value.strip().lower()
    if normalized in {'1', 'true', 'yes', 'on'}:
        return True
    if normalized in {'0', 'false', 'no', 'off'}:
        return False
    return None


def _read_only_passkey_flag(cfg: dict) -> bool | None:
    """Passkey feature flag for one scope: env wins, then ``config.yaml``.

    ``None`` means the configured value is malformed (fail closed).
    """
    env_value = os.getenv('HERMES_WEBUI_PASSKEY', '')
    if env_value:
        return _read_only_bool_string(env_value)
    raw = cfg.get('webui_passkey_enabled')
    if raw is None:
        return False
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        return _read_only_bool_string(raw)
    return None


def _read_only_passkey_credentials() -> bool | None:
    """Direct read of ``STATE_DIR/passkeys.json``.

    ``True`` when at least one credential is registered; ``False`` when the
    store is absent or empty (readable); ``None`` when the store is
    unreadable or malformed (fail closed).
    """
    path = STATE_DIR / 'passkeys.json'
    try:
        st = path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode):
        return None
    raw = _read_regular_file_no_follow(path, _READ_ONLY_MAX_PASSKEYS_BYTES)
    if raw is None:
        return None
    try:
        data = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(data, list):
        return None
    return any(
        isinstance(entry, dict) and isinstance(entry.get('id'), str) and entry.get('id')
        for entry in data
    )


def _read_only_passkey_posture(cfg: dict) -> str:
    flag = _read_only_passkey_flag(cfg)
    if flag is None:
        return _READ_ONLY_UNAVAILABLE
    if not flag:
        return _READ_ONLY_DISABLED
    credentials = _read_only_passkey_credentials()
    if credentials is None:
        return _READ_ONLY_UNAVAILABLE
    return _READ_ONLY_ENABLED if credentials else _READ_ONLY_DISABLED


def _read_only_oidc_posture(cfg: dict) -> str:
    """OIDC posture for one scope.

    Enabled only when all four fields (issuer, client_id, allow_claim,
    allow_values) are set; partially configured or malformed security state
    is ``unavailable`` (fail closed, never disabled).
    """
    raw = cfg.get('webui_oidc')
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        return _READ_ONLY_UNAVAILABLE

    def pick(name: str, env_name: str) -> str:
        env_value = os.getenv(env_name)
        value = env_value if env_value is not None else raw.get(name)
        return str(value or '').strip()

    issuer = pick('issuer', 'HERMES_WEBUI_OIDC_ISSUER')
    client_id = pick('client_id', 'HERMES_WEBUI_OIDC_CLIENT_ID')
    allow_claim = pick('allow_claim', 'HERMES_WEBUI_OIDC_ALLOW_CLAIM')
    allow_env = os.getenv('HERMES_WEBUI_OIDC_ALLOW_VALUES')
    allow_values = allow_env if allow_env is not None else raw.get('allow_values')
    allow_values = str(allow_values or '').strip()
    present = [issuer, client_id, allow_claim, allow_values]
    if all(present):
        return _READ_ONLY_ENABLED
    if any(present):
        return _READ_ONLY_UNAVAILABLE  # partially configured security state
    return _READ_ONLY_DISABLED


def _read_only_password_env_posture() -> str:
    return (
        _READ_ONLY_ENABLED
        if os.getenv('HERMES_WEBUI_PASSWORD', '').strip()
        else _READ_ONLY_DISABLED
    )


def _read_only_settings_hash_posture() -> str:
    """Configured non-empty password hash in ``STATE_DIR/settings.json``.

    Missing file is readable-disabled. Unreadable, symlinked, malformed,
    non-dict, or non-string hash values are ``unavailable`` (fail closed).
    """
    path = STATE_DIR / 'settings.json'
    try:
        st = path.lstat()
    except FileNotFoundError:
        return _READ_ONLY_DISABLED
    except OSError:
        return _READ_ONLY_UNAVAILABLE
    if not stat.S_ISREG(st.st_mode):
        return _READ_ONLY_UNAVAILABLE
    raw = _read_regular_file_no_follow(path, _READ_ONLY_MAX_SETTINGS_BYTES)
    if raw is None:
        return _READ_ONLY_UNAVAILABLE
    try:
        data = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return _READ_ONLY_UNAVAILABLE
    if not isinstance(data, dict):
        return _READ_ONLY_UNAVAILABLE
    value = data.get('password_hash')
    if value is None:
        return _READ_ONLY_DISABLED
    if isinstance(value, str):
        return _READ_ONLY_ENABLED if value else _READ_ONLY_DISABLED
    return _READ_ONLY_UNAVAILABLE


def _read_only_trusted_header_posture() -> str:
    return (
        _READ_ONLY_ENABLED
        if os.getenv('HERMES_WEBUI_TRUSTED_AUTH_HEADER', '').strip()
        else _READ_ONLY_DISABLED
    )


def read_only_auth_enabled() -> str:
    """Fail-closed tri-state deployment-wide auth union (§7).

    Returns exactly one of ``AUTH_ENABLED``, ``AUTH_DISABLED``,
    ``AUTH_STATE_UNAVAILABLE``.

    The union covers (a) ``HERMES_WEBUI_PASSWORD``, (b) the configured
    password hash in ``STATE_DIR/settings.json``, (c) the root profile
    ``config.yaml``, and (d) every named-profile ``config.yaml`` enumerated
    DIRECTLY under the profile registry root — no discovery caches, no alias
    caches, no ``_profiles_match()`` population, no directory creation, no
    migration, no profile-registry refresh.

    Postures are evaluated in precedence order: password (env) > configured
    password hash > passkey > OIDC > trusted-header. The union is the OR of
    all readable states: ``AUTH_ENABLED`` when any readable posture is enabled
    anywhere in the union; ``AUTH_DISABLED`` only when every union member is
    readable and all are disabled. Unreadable, malformed, or partially
    configured security state in the global scope or ANY profile home is
    ``AUTH_STATE_UNAVAILABLE`` — never ``AUTH_DISABLED``; a state of "unknown"
    is never treated as "disabled" and never silently ignored.

    This seam never generates or loads keys (``_load_key``/``_pbkdf2_key``/
    ``_signing_key``), never hashes a password, never populates
    ``_AUTH_HASH_CACHE``/``_PBKDF2_KEY_CACHE``/``_SIGNING_KEY_CACHE`` or any
    settings/config cache, never writes or migrates settings/config, never
    consults the process active profile, and never touches the request-profile
    TLS slot.
    """
    postures = [
        # Precedence: password (env) > configured password hash.
        _read_only_password_env_posture(),
        _read_only_settings_hash_posture(),
    ]
    for _name, home in _read_only_profile_scopes():
        status, cfg = _read_only_profile_config(home)
        if status == _CFG_UNREADABLE:
            return AUTH_STATE_UNAVAILABLE
        postures.append(_read_only_passkey_posture(cfg))
        postures.append(_read_only_oidc_posture(cfg))
    # Precedence tail: trusted-header.
    postures.append(_read_only_trusted_header_posture())
    if any(p == _READ_ONLY_UNAVAILABLE for p in postures):
        return AUTH_STATE_UNAVAILABLE
    if any(p == _READ_ONLY_ENABLED for p in postures):
        return AUTH_ENABLED
    return AUTH_DISABLED
