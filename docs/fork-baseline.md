# Fork Baseline — issue #45

Canonical WebUI development baseline for the Hermex fork
(`github.com/ebreen/hermes-webui`). GitHub CI is the clean-run authority;
host-specific notes are recorded here and in the issue evidence.

## Repositories

| Role | Remote | Branch | Pin |
|---|---|---|---|
| Owner origin | `https://github.com/ebreen/hermes-webui.git` | `master` (clean upstream) | `d42dae81` initial pin |
| Customizations | same | `live-customizations` | merged onto `d42dae81` |
| Inherited upstream (read-only) | `https://github.com/nesquena/hermes-webui.git` | `master` | — |

## Live vs dev matrix

| Aspect | Live (production) | Dev (fork baseline) |
|---|---|---|
| Checkout | `/home/hermes/hermes-webui` (tracking upstream, 8 local mods, NEVER mutated by this slice) | `/home/hermes/projects/hermes-webui` (owner origin + read-only upstream) |
| Port | `8787` (0.0.0.0) | `8788` (isolated, for smoke) |
| Process | raw `python3 bootstrap.py` (pid recorded at inventory) | disposable smoke process |
| State | `~/.hermes` + live state dir | `HERMES_HOME=/tmp/hermex-webui-dev-home`, `HERMES_WEBUI_STATE_DIR=/tmp/hermex-webui-dev-state` |
| Secrets | live `.env` (never printed; backup at `/home/hermes/backups/hermes-webui-live-env-2026-08-09.env`, mode 600) | dev password only, generated per smoke |
| Customizations | applied as uncommitted mods (8 files) | preserved as `patches/live-baseline-980e98dc.patch` + committed on `live-customizations` |
| Auth | password-only (`HERMES_WEBUI_PASSWORD`) | password-only (dev password) |

## Customizations preserved (live → fork)

Reasoning-effort `max`/`ultra` support with capability-gated fallbacks
(capped at `xhigh` unless authoritative metadata advertises higher), Codex
catalog-driven exact effort levels, UI labels/options, and matching test
updates. Source of truth: `patches/live-baseline-980e98dc.patch`.

## Baseline checks

1. `./scripts/test.sh` (desktop suite) — host-specific: the 11 browser/
   playwright test files are excluded locally (playwright not installed);
   they run on GitHub CI (`Tests` workflow, sharded matrix).
2. GitHub CI `Tests` workflow on PRs — the clean-run authority.
3. Health/auth smoke: boot with isolated `HERMES_HOME`/`HERMES_WEBUI_STATE_DIR`/
   port; unauthenticated requests must be blocked (302/`Authentication required`);
   `POST /api/auth/login` with the dev password must return 200 and an authed
   `GET /` must return 200. Verified 2026-08-09 on the merged customization tree.
4. SELinux note: the upstream atomic-write suite assumes no `security.selinux`
   xattr; this host records host-specific skips/failures there. CI is the
   authority for clean runs.

## Recording

- `WEBUI_FORK_TESTED_SHA` = the exact green fork commit recorded in the
  hermex contract after CI passes (issue #45 acceptance).
- Paired Hermes Agent: v0.20.0 (2026.8.3) — the agent SHA named with the
  test evidence.

## Rollback

- Delete the isolated dev checkout `/home/hermes/projects/hermes-webui`
  (and its smoke processes); nothing else was touched.
- The live checkout `/home/hermes/hermes-webui` is byte-identical to its
  pre-slice state; the fork has no deployment authority and no live
  process, port, state, or file was changed.
- Restore the live `.env` from
  `/home/hermes/backups/hermes-webui-live-env-2026-08-09.env` if ever needed.
