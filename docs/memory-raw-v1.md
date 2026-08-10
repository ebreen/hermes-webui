# Raw Memory Source API v1 (`/api/memory/raw`) — WebUI fork contract

Binding contract: [`ebreen/hermex#58`](https://github.com/ebreen/hermex/issues/58)
(v6). Machine-readable normative wire contract:
[`tests/fixtures/memory_raw_v1.json`](../tests/fixtures/memory_raw_v1.json) — the
verified 506-line / 18,702-byte fixture
(`memory_raw_v1_complete_response_cases`, SHA-256
`e1d6c0c17695f7f21bc69ba5780cab50bd699fedc9d89b1131170b50b324f7a5`) embedded
verbatim plus the §13 contract members (endpoint, header rules,
`if_none_match` grammar, request-framing rules, error table, and the exact
capability objects).

> **Status: PR 1 (anchored reader module).** `api/memory_sources.py`, its
> direct module tests, the fixture, and this document exist. There is **no
> public dispatch and no capability yet**: the route is not reachable over
> HTTP and `/api/system/health` does not advertise `memory_raw_v1`. That is
> PR 2 (§16 of the contract).

## 1. Route shape (final, PR 2 dispatch)

```text
GET /api/memory/raw?source=memory|user|soul|project_context[&session_id=<authorized-session-id>]
```

- Exact path match only: `/api/memory/raw/`, `/api/memory/rawish`, and
  encoded-path aliases are **not** this route.
- `GET` is the only allowed method. `HEAD`/`OPTIONS`/`POST`/`PUT`/`PATCH`/
  `DELETE` return **405** `{"error":"method_not_allowed"}` with `Allow: GET`
  (HEAD is bodyless and omits `Content-Length`/`Content-Type`). Positive
  `Content-Length` or any `Transfer-Encoding` on any exact-path method forces
  `Connection: close` without consuming the body; a lone `Content-Length: 0`
  may stay keep-alive.
- The branch runs after only request parsing and per-request state reset,
  before profile-cookie extraction, generic auth, session visibility, CSRF,
  body reads, global OPTIONS, and generic 404. It never falls through to the
  generic handlers and never queues `Set-Cookie`.
- The route is read-only: no write, mutation, cache, or provider side effect.

## 2. Fixed sources and feature gates (§9)

| selector | fixed source (relative to the authorized Profile home) | envelope `name` |
|---|---|---|
| `memory` | `memories/MEMORY.md` | `MEMORY.md` |
| `user` | `memories/USER.md` | `USER.md` |
| `soul` | `SOUL.md` | `SOUL.md` |
| `project_context` | first fixed candidate in the selected authorized scan root (trusted workspace first, then only through an independently authorized nearest Git root, inclusive) | candidate basename only |

- Resolution happens **only** through the immutable
  `AuthorizedRawProfileContext` (`bound_profile`, `profile_home`,
  `auth_session_id`, optional session-record view) passed by parameter into
  every pure resolver. The context is never stored in a module global,
  thread-local, or process-TLS slot. No resolver reads the process active
  Profile.
- Feature gates per authorized Profile: `memory.memory_enabled: false` ⇒
  `source=memory` is **403** `{"error":"forbidden"}` before any file metadata;
  `memory.user_profile_enabled: false` ⇒ `source=user` is **403**. Missing or
  malformed `memory` config defaults to enabled; `soul` is not controlled by
  either flag. Gates are read through `read_only_profile_config_snapshot(ctx)`
  — a direct bounded no-follow read of that Profile's `config.yaml` that never
  calls `get_config()`, `get_config_snapshot()`, `_refresh_config_cache()`,
  `_cfg_cache`, process-global config aliases, or any writer.
- `project_context` without `session_id` uses the authorized Profile's
  profile-scoped default workspace (`read_only_profile_default_workspace`):
  that Profile's own `last_workspace.txt` first, then config keys in the
  existing precedence `workspace` → `default_workspace` → `terminal.cwd`. The
  default Profile owns the global WebUI `STATE_DIR`; a named Profile owns
  `{profile_home}/webui_state`. No mkdir, no migration, no
  `_profile_state_dir()`, no global `LAST_WORKSPACE_FILE`/`TERMINAL_CWD`/
  `DEFAULT_WORKSPACE` fallback. A remote/non-local terminal backend, or a
  missing/empty/malformed/non-directory default, is **404** `not_found`.
- `project_context` with `session_id` uses `read_only_session_metadata(ctx,
  session_id)`: the **WebUI** sidecar `STATE_DIR/sessions/<id>.json` (never
  the auth `STATE_DIR/.sessions.json` store), bounded safe session-ID grammar
  (≤ 256 bytes, `[A-Za-z0-9_-]`), bounded 64 KiB metadata prefix containing
  `workspace`, and a `profile` field (missing/empty = root/default alias).
  Never instantiates `Session`; never parses `messages` to recover fields;
  over-cap/malformed/replaced/short reads fail closed. The stored workspace is
  revalidated through `read_only_resolve_trusted_workspace` at read time.
  Unknown/expired/foreign/blank-workspace/malformed-profile/no-longer-trusted
  sessions are **404** `{"error":"not_found"}` — never a fallback to the
  active workspace.
- Trust (`read_only_resolve_trusted_workspace`): non-empty candidate only;
  home carve-out, system-root rejection, and the profile-local saved-workspace
  list read directly (never `load_workspaces()`/`_clean_workspace_list()`/
  `_migrate_global_workspaces()`/`_profile_state_dir()`/writers); remote
  terminal candidates rejected; malformed/unreadable state fails closed.
- Candidate order is fixed and workspace-first ascending to the authorized Git
  root: at each directory `[trusted_workspace, …, authorized_git_root]` try
  `.hermes.md`, then `HERMES.md`; then at the trusted workspace
  `AGENTS.md`, `agents.md`, `CLAUDE.md`, `claude.md`, `.cursorrules`; finally
  `.cursor/rules/*.mdc` sorted by normalized relative path. The nearest Git
  root (inclusive) is independently authorized before any ancestor candidate
  is inspected; an unauthorized ancestor is never inspected and the scan stays
  at the trusted workspace. A root-level candidate never wins over a valid
  workspace-level candidate merely because the root is the scan anchor.
- Empty files are valid zero-byte sources. Missing source, non-regular file,
  directory, FIFO, device, symlink, outside-root candidate, and denied
  candidate are **404**. No response or log contains an absolute path,
  workspace, or Profile home; the envelope carries `name` (bounded basename)
  only — no path/workspace/profile fields.

## 3. Anchored race-resistant reader (§10)

`read_anchored_source(anchor, components, limit)` in `api/memory_sources.py`:

- POSIX only (`dir_fd`/openat-equivalent, `O_NOFOLLOW`, `O_DIRECTORY`,
  `O_CLOEXEC`, `O_NONBLOCK`, no-follow stats, descriptor identity). Unsupported
  platforms ⇒ **503** `{"error":"raw_unavailable"}`, no source read.
- The anchor is the independently authorized scan root. Its lexical parent
  directory FD is held from before the anchor open through the post-read
  check; the anchor entry is no-follow-statted from that parent, opened
  relative to it with `O_NOFOLLOW|O_DIRECTORY`, `fstat`ed immediately, and its
  `(st_dev, st_ino, st_mode, st_size, st_mtime_ns, st_ctime_ns)` tuple compared
  to the pre-open entry. After reading, the anchor entry and FD are checked
  again. A root anchor with no stable held parent entry is refused
  (`raw_unavailable`).
- Every nested namespace component is traversed one at a time relative to the
  held anchor FD (`a` then `b` for `a/b/file`), each opened
  `O_NOFOLLOW|O_DIRECTORY`, with entry/FD identity captured before and after
  the read. The final entry is opened `O_NOFOLLOW|O_NONBLOCK` and must be a
  regular file — never a FIFO, device, socket, directory, or symlink.
- Bounded short-read loop: read at most exactly `limit + 1` bytes; a positive
  short read is followed by another read (a stable regular file delivered in
  several short chunks is **200**). True EOF at the captured stable size at or
  below the limit succeeds; the extra byte beyond the limit ⇒ **413**
  `{"error":"source_too_large"}` with no partial `data`; EOF before the stable
  size, or any post-read descriptor/namespace identity, mode, size, timestamp,
  or namespace mismatch (delete/unlink, symlink swap, atomic replacement,
  parent/component swap, same-size in-place rewrite) ⇒ **409**
  `{"error":"source_changed"}` with no partial data. Mutation/race checks take
  precedence over a success or 413 result. Content hashing alone is never
  mutation protection.
- The only size setting is the deployment env key
  `HERMES_WEBUI_MEMORY_RAW_MAX_BYTES` (no query override). Unset ⇒ `8388608`
  (8 MiB). Present values must be ASCII decimal digits only and parse to an
  integer in `1..16777216` (16 MiB); any invalid/out-of-range value is not
  clamped or defaulted: **503** `raw_unavailable` until corrected.
- Four process-local `threading.BoundedSemaphore(4)` slots are held from
  immediately before source resolution/read through JSON serialization. A
  request that finds no slot ⇒ **503** `{"error":"raw_read_busy"}` with
  `Retry-After: 1` without opening a source. Slots always release on success
  and every error path.

## 4. Envelope and canonical representation (§11)

```json
{
  "schema_version": 1,
  "source": "memory",
  "name": "MEMORY.md",
  "content_type": "text/markdown",
  "byte_length": 12,
  "byte_encoding": "base64",
  "data": "IyBOb3RlCmxpbmUK",
  "checksum": {
    "algorithm": "sha-256",
    "value": "bb89a6e8128d049f4225932f9de463fef2e992c8a439b20ebb17b3792ddac3d2"
  },
  "source_version": "sha256:bb89a6e8128d049f4225932f9de463fef2e992c8a439b20ebb17b3792ddac3d2"
}
```

- `data` is standard padded RFC 4648 base64 (standard alphabet, no URL-safe
  alphabet, no whitespace or line wrapping) of the **original bytes** —
  including invalid UTF-8, NUL bytes, BOMs, and lone CRs; nothing is decoded,
  redacted, or normalized. `byte_length` is the decoded-byte length.
- `checksum.value` and `source_version` are SHA-256 over the original source
  bytes and are identical except for the `sha256:` prefix. They remain
  source-byte identity even when the response representation carries a
  different `name` or other metadata. They are **never** used as the ETag.
- The uncompressed 200 body is serialized exactly as UTF-8 with:

```python
json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")
```

  No trailing newline. Compression is disabled unconditionally (no
  `Content-Encoding`, no `Vary`, regardless of `Accept-Encoding`).
- 200 headers: `Content-Type: application/json; charset=utf-8`,
  `Cache-Control: private, no-store`, current HTTP `Date`, strong
  representation ETag `"repr-sha256:<64 lowercase hex>"` (SHA-256 over the
  complete uncompressed 200 JSON UTF-8 bytes — deliberately distinct from
  `checksum`/`source_version`), and `Content-Length` equal to the exact UTF-8
  length of the body.
- `If-None-Match`: combine all field instances in received order, comma-parse
  one combined value with OWS-trimmed members; accept `*` and tokens of the
  exact form `"repr-sha256:<64 lowercase hex>"`; `W/"…"` compares equal for
  this GET; malformed members are ignored. A match after the complete
  auth/provenance gate and a stable constructed representation returns an
  authenticated bodyless **304** with current `ETag`/`Date`/`Cache-Control`
  and **no** `Content-Length`, `Content-Type`, `Content-Encoding`, `Vary`, or
  trailers (never `Content-Length: 0`). A missing, mutated, unsupported,
  disabled, or oversized source is never converted into 304.

### Error table

| case | status | body |
|---:|---|---|
| malformed/duplicate/unknown query | 400 | `{"error":"invalid_request"}` |
| missing/invalid/expired/duplicate/empty cookie | 401 | `{"error":"authentication_required"}` |
| auth disabled, profile/provenance mismatch, disabled source | 403 | `{"error":"forbidden"}` |
| missing/foreign session, invalid default workspace, missing source, unsafe candidate | 404 | `{"error":"not_found"}` |
| source mutation/short-read EOF before stable size/identity/namespace mismatch | 409 | `{"error":"source_changed"}` |
| source exceeds configured limit | 413 | `{"error":"source_too_large"}` |
| four-read-slot exhaustion | 503 | `{"error":"raw_read_busy"}` + `Retry-After: 1` |
| invalid limit or unsupported read guarantee or `auth_state_unavailable` | 503 | `{"error":"raw_unavailable"}` |
| non-GET method | 405 | `{"error":"method_not_allowed"}` + `Allow: GET` (bodyless HEAD) |

All error bodies are compact JSON with exact `Content-Length`, no exception
text, no selectors, paths, or session data.

## 5. Authentication, authority, and provenance (PR 0 seams + §8)

- Pure PR 0 seams in `api/auth.py` perform the gate: the tri-state
  `read_only_auth_enabled()` deployment-wide union (password env > configured
  hash > passkey > OIDC > trusted-header across the root profile and **every**
  named profile via direct profile-home enumeration; unreadable/malformed
  security state is `auth_state_unavailable` ⇒ 503 `raw_unavailable`, never
  auth-disabled), `read_only_incoming_cookie_session_info()` (direct no-follow
  `STATE_DIR/.signing_key` and `STATE_DIR/.sessions.json` reads; expiry check;
  detached bound-session record), and `read_only_verify_profile_cookie()`
  (pure token/HMAC comparison). None of them generates keys, prunes/persists
  sessions, mints/queues cookies, populates caches, or touches the request
  Profile TLS slot.
- `bound_profile` is derived from the validated session record under the
  existing root/default alias rules: the literal `default` and any profile the
  registry identifies as the renamed root/default are equivalent; a
  missing/empty profile is a root-profile row. With no profile cookie the
  bound profile is the only candidate — the process/TLS active Profile is
  **never** a candidate. In isolated deployment mode the pinned deployment
  profile must match `bound_profile` under the same alias rules; any mismatch
  is 403 with no source work. A valid profile cookie may confirm the request
  Profile only when it resolves to the same bound Profile; invalid, empty,
  unbound, malformed, mismatching, duplicate, or conflicting profile values
  are 403, never "last one wins".
- Combined-cookie cardinality: all `Cookie` field instances are combined in
  received order; the configured auth cookie name (`HERMES_WEBUI_COOKIE_NAME`,
  default `hermes_session`) occurs exactly once; the profile cookie occurs
  zero-or-one times. Malformed cookie syntax in any field is rejected.
- Provenance (`validate_provenance` in `api/memory_sources.py`, §8 steps 5-8):
  exactly one `Host` field with strict syntax (no list, whitespace
  alternatives, userinfo, path/query, malformed DNS/IPv6, invalid port);
  canonical external origin = exact scheme + normalized host + effective port
  (default ports normalized); `X-Forwarded-Proto`/`X-Forwarded-Host` are used
  only under `HERMES_WEBUI_TRUST_FORWARDED_PROTO`/`_HOST` and fail closed on
  comma chains/duplicates/malformed values; `Origin`/`Referer`, when present,
  must exactly equal the canonical origin (`Origin: null`, userinfo,
  malformed, path/port/scheme mismatches, and conflicting values rejected);
  every `Sec-Fetch-*` field is inspected — one per name, no list syntax, only
  `Sec-Fetch-Site`/`Mode`/`Dest`; if any Fetch-Metadata field is present,
  `Sec-Fetch-Site` must be exactly `same-origin`, with `Mode` ∈
  {`cors`, `same-origin`} and `Dest` = `empty`; unknown names (e.g.
  `Sec-Fetch-User`) rejected. `HERMES_WEBUI_ALLOWED_ORIGINS` never grants an
  exception; `If-None-Match` never bypasses auth/provenance; native requests
  with no Origin/Referer/Fetch-Metadata are allowed only after the auth gate.

## 6. No-mutation boundary (§5)

The raw path never calls `set_request_profile()`, `clear_request_profile()`,
`get_request_profile()`, `get_active_profile_name()`, `get_profile_cookie()`,
`get_profile_cookie_name()`, `parse_cookie()`, `verify_profile_cookie_value()`,
`verify_session()`, `get_session_info()`, `check_auth()`,
`ensure_trusted_auth_session()`, `is_auth_enabled()`, `is_password_auth_enabled()`,
`get_password_hash()`, `_load_key()`, `_pbkdf2_key()`, `_signing_key()`, or any
helper that can generate a key, prune/persist sessions, queue cookies,
populate alias/discovery caches, warn-once, or switch the process-global
Profile. It never reads or writes the request thread-local Profile slot —
before, during, or after the response — and no module-global/thread-local
storage holds the `AuthorizedRawProfileContext`. Auth-cookie records
(`STATE_DIR/.sessions.json`), the WebUI session sidecars
(`STATE_DIR/sessions/<id>.json`), and Profile memory/config files are distinct
stores and are never substituted for one another.

## 7. Capability advertisement (PR 2, §12)

The additive field is introduced by #58 and does not exist at the pinned SHA:

```json
"capabilities": {
  "memory_raw_v1": {
    "available": true,
    "endpoint": "/api/memory/raw",
    "schema_version": 1,
    "sources": ["memory", "user", "soul", "project_context"],
    "representation_etag": {
      "algorithm": "sha-256",
      "scope": "canonical_uncompressed_200_json_utf8",
      "format": "quoted_repr_sha256",
      "pattern": "\"repr-sha256:<64 lowercase hex>\""
    },
    "conditional_requests": {
      "request_header": "If-None-Match",
      "accepted_forms": ["strong", "weak", "*"],
      "weak_comparison": true,
      "malformed_members": "ignored",
      "304_body": "absent"
    }
  }
}
```

Unsupported: `"capabilities": { "memory_raw_v1": { "available": false } }`.
`available` is true only when the pure auth posture is `auth_enabled`, the
authoritative `STATE_DIR/.signing_key` is present/readable/regular/valid, the
configured limit is valid, and the platform provides every promised anchored/
no-follow/descriptor-and-namespace mutation guarantee. `auth_state_unavailable`
is capability false. Until PR 2, the field is absent and the route is not
dispatched.

## 8. Logging and framing (PR 2)

All raw normal, exception, and disconnect logs use the fixed route label
`/api/memory/raw` and only method, status/exception class, and bounded timing
— never `self.path`, query, selectors, session IDs, cookies, source bytes,
workspace, absolute paths, or traceback text containing them. The raw writer
owns `end_headers()`/`wfile.write()` and disconnect handling; it never reuses
`api.helpers.j()`/`_safe_write()` and never flushes a queued auth cookie.
A forced disconnect with `?session_id=SECRET` must log the fixed label and
none of the query/session text.

## 9. Fixture and tests

- `tests/fixtures/memory_raw_v1.json` — the verified fixture embedded verbatim
  (fixture identity `memory_raw_v1_complete_response_cases`,
  `schema_version: 1`, `canonical_case_mapping`, nine byte cases with
  `source_base64`/`source_byte_length`/`source_sha256`/`source_version` and
  `canonical_200` chunked body base64/`body_byte_length`/`Content-Length`/
  `representation_sha256`/quoted ETag, the exact bodyless `conditional_304`,
  all nine `provenance_cases`, `provenance_precondition`) plus the fixed
  contract members: `endpoint`, `headers` rules, `if_none_match` grammar,
  `request_framing` rules, the `errors` table, the exact
  `capability_supported`/`capability_unsupported` objects, and the
  `etag_scope` statement (ETags are scoped to the named canonical full-response
  envelope; byte cases alone do not receive a source-hash ETag).
- `tests/test_memory_sources_pr1.py` — PR 1 RED/GREEN matrix exercising the
  module directly: query parsing, provenance vectors, fixed-source resolution
  (all four selectors, gates, default/session workspaces, Git-root candidate
  order), byte-faithful reads, the bounded short-read loop and race outcomes,
  envelope/serializer/ETag semantics, every fixture byte case and the 304,
  limit configuration, the 4-slot semaphore, and the no-mutation suite
  (mutating helpers monkeypatched to raise; TLS slot untouched; no files
  created).
- PR 0's `tests/test_memory_raw_pr0_seams.py` (82 tests) remains the seam
  suite; the existing `/api/memory` (decoded/redacted) and
  `/api/memory/write` (POST-only with its gates) behavior is unchanged.
- Run: `./scripts/test.sh tests/test_memory_sources_pr1.py
  tests/test_memory_raw_pr0_seams.py tests/test_issue6498_memory_config_gates.py
  tests/test_memory_write_symlink_guard.py` and the full WebUI command from
  `TESTING.md`/CI before merging.

## 10. Rollback and exclusions

Rollback is additive and reversible, reverse per-slice: revert PR 2 (dispatch,
raw writer/logging/framing, capability field) before PR 1
(`api/memory_sources.py`, raw tests/fixture/docs) before PR 0 (pure seams).
Explicit exclusions: gzip/negotiated compression; source-byte hashes as
representation ETags; arbitrary file or workspace reads; Profile-path
selectors; trusted-header/API-key auth; CORS or allowed-origin exceptions;
CSRF tokens for GET; text decoding/redaction/frontmatter normalization;
source mutation/repair or cache/index/workspace persistence; offline raw
caching in #19 V1; write-route/UI changes in #58; request-profile TLS
mutation on the raw path; process/TLS active-profile authority on the raw
path; advertising raw support on platforms that cannot prove the anchored
race-safe read or whose security state cannot be read.
