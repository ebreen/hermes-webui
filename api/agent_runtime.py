"""Fail-closed guard for in-process Hermes Agent source revisions.

Hermes WebUI currently imports ``run_agent.AIAgent`` into its long-lived server
process. If the Agent checkout changes while that process is alive, Python may
combine already-cached modules with newly-read source. Refuse to reuse that
mixed runtime and require a clean WebUI restart instead.
"""

from __future__ import annotations

from pathlib import Path
import sys
import subprocess
import threading

# Retain the discovered path as a diagnostic/test-visible compatibility value;
# runtime identity is deliberately captured from the loaded module below.
from api.config import _AGENT_DIR  # noqa: F401

_RESTART_MESSAGE = (
    "Hermes Agent was updated while Hermes WebUI was running. "
    "Restart Hermes WebUI before retrying this action."
)


def _read_agent_revision(
    agent_dir: Path | None,
    *,
    module_path: Path | None = None,
) -> str | None:
    """Return the loaded Agent checkout HEAD, or ``None`` if it is not tracked."""
    if agent_dir is None:
        return None

    if module_path is None:
        module = sys.modules.get("run_agent")
        module_file = getattr(module, "__file__", None)
        if not module_file:
            return None
        try:
            module_path = Path(module_file).resolve()
        except (OSError, RuntimeError, TypeError):
            return None

    try:
        worktree_result = subprocess.run(
            ["git", "-C", str(agent_dir), "rev-parse", "--show-toplevel"],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
        if worktree_result.returncode != 0:
            return None
        worktree = Path(worktree_result.stdout.strip()).resolve()
        relative_module = module_path.relative_to(worktree).as_posix()
        tracked_result = subprocess.run(
            [
                "git",
                "--literal-pathspecs",
                "-C",
                str(worktree),
                "ls-files",
                "--error-unmatch",
                "--",
                relative_module,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
        if tracked_result.returncode != 0:
            return None
        revision_result = subprocess.run(
            ["git", "-C", str(worktree), "rev-parse", "--verify", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired, RuntimeError, ValueError):
        return None

    revision = revision_result.stdout.strip()
    return revision if revision_result.returncode == 0 and revision else None


_AGENT_SOURCE_DIR: Path | None = None
_AGENT_MODULE_PATH: Path | None = None
_AGENT_REVISION: str | None = None
_AIAgent = None
_RUNTIME_LOCK = threading.Lock()


class AgentRuntimeChangedError(RuntimeError):
    """Raised when the loaded Agent runtime no longer matches its source tree."""


class ProviderRoutingConfigError(ValueError):
    """Raised when ``provider_routing`` cannot be enforced as an egress policy.

    Fails closed: a malformed or unenforceable routing configuration must
    never silently degrade to an unrestricted OpenRouter provider selection.
    """


#: Configured ``provider_routing`` keys that carry egress policy. When one of
#: these is set but the Hermes Agent runtime does not accept the matching
#: ``AIAgent`` parameter, constructing an agent without that control would
#: silently widen network egress — so construction fails instead.
_POLICY_KEYS = frozenset(
    {"only", "ignore", "order", "require_parameters", "data_collection"}
)


def provider_routing_agent_kwargs(
    config_data: dict | None = None,
    *,
    supported_params: set[str] | None = None,
    agent_class=None,
) -> dict:
    """Map Hermes ``provider_routing`` config to ``AIAgent`` kwargs.

    This is an egress-policy boundary: a configured strict allowlist must not
    silently become unrestricted (which would let OpenRouter pick providers
    outside ``only``). It therefore fails closed:

    * A present-but-malformed ``provider_routing`` (not a mapping) raises
      :class:`ProviderRoutingConfigError` rather than being treated as absent.
    * When a configured policy field is not supported by the Hermes Agent
      runtime, construction fails rather than dropping that control.
    * When ``config_data`` is omitted, the active profile's config is captured
      through :func:`api.config.get_config_snapshot` so a concurrent profile
      switch cannot hand one profile another profile's routing (or a mutable
      shared cache).

    ``supported_params`` may be provided directly by callers that already know
    the AIAgent parameter set (e.g. the streaming path's ``_agent_params``);
    otherwise it is derived from ``agent_class`` when given.
    """
    if config_data is None:
        from api.config import get_config_snapshot  # noqa: PLC0415

        config_data = get_config_snapshot()
    if not isinstance(config_data, dict):
        # An explicit non-dict config is a caller bug. Coercing it to {} would
        # silently lose the active profile's allowlist (fail-open), so reject.
        raise ProviderRoutingConfigError(
            "config_data must be a mapping; refusing to derive an unrestricted "
            f"provider allowlist from {type(config_data).__name__}"
        )

    routing = config_data.get("provider_routing")
    if routing is None:
        routing = {}
    if not isinstance(routing, dict):
        raise ProviderRoutingConfigError(
            "provider_routing must be a mapping in config; refusing to run with "
            f"an unrestricted provider allowlist (got {type(routing).__name__})"
        )

    kwargs = {
        "providers_allowed": routing.get("only"),
        "providers_ignored": routing.get("ignore"),
        "providers_order": routing.get("order"),
        "provider_sort": routing.get("sort"),
        "provider_require_parameters": routing.get("require_parameters", False),
        "provider_data_collection": routing.get("data_collection"),
    }

    # A mapping whose policy values are not sane shapes is as unenforceable as
    # a non-mapping: reject it rather than forward garbage to a provider.
    _validate_routing_shapes(routing)

    if supported_params is None and agent_class is not None:
        try:
            import inspect

            parameters = inspect.signature(agent_class.__init__).parameters
            if not any(
                parameter.kind is inspect.Parameter.VAR_KEYWORD
                for parameter in parameters.values()
            ):
                supported_params = set(parameters)
        except (TypeError, ValueError):
            supported_params = None

    if supported_params is not None:
        missing_policy = [
            key
            for key in _POLICY_KEYS
            if routing.get(key) not in (None, False, [], {})
            and _param_for(key, kwargs) not in supported_params
        ]
        if missing_policy:
            raise ProviderRoutingConfigError(
                "Hermes Agent runtime does not support provider-routing "
                f"parameter(s): {sorted(missing_policy)}; refusing to construct "
                "an agent without its configured egress allowlist"
            )
        kwargs = {key: value for key, value in kwargs.items() if key in supported_params}
    return kwargs


def _param_for(routing_key: str, kwargs: dict) -> str:
    by_routing_key = {
        "only": "providers_allowed",
        "ignore": "providers_ignored",
        "order": "providers_order",
        "sort": "provider_sort",
        "require_parameters": "provider_require_parameters",
        "data_collection": "provider_data_collection",
    }
    return by_routing_key.get(routing_key, routing_key)


def _validate_routing_shapes(routing: dict) -> None:
    """Reject configured routing values that cannot be enforced.

    ``only``/``order``/``ignore`` must be non-empty sequences of provider names
    (a bare truthy non-sequence is a config typo). Fails closed: an ambiguous
    value must not silently act as an empty allowlist and widen egress.
    """
    for key in ("only", "order", "ignore"):
        value = routing.get(key)
        if value in (None, []):
            continue
        if not isinstance(value, (list, tuple)) or not all(
            isinstance(provider, str) and provider
            for provider in value
        ):
            raise ProviderRoutingConfigError(
                f"provider_routing.{key} must be a list of provider slugs; "
                f"refusing to run with an ambiguous allowlist (got {value!r})"
            )
    sort = routing.get("sort")
    if sort is not None and (not isinstance(sort, str) or not sort):
        raise ProviderRoutingConfigError(
            "provider_routing.sort must be a non-empty string; "
            f"refusing to run with an ambiguous routing preference (got {sort!r})"
        )
    require = routing.get("require_parameters")
    if require not in (None, True, False):
        raise ProviderRoutingConfigError(
            "provider_routing.require_parameters must be a boolean; "
            f"refusing to run with an ambiguous routing control (got {require!r})"
        )
    data_collection = routing.get("data_collection")
    if data_collection not in (None, "allow", "deny"):
        raise ProviderRoutingConfigError(
            "provider_routing.data_collection must be 'allow' or 'deny'; "
            f"refusing to run with an ambiguous data policy (got {data_collection!r})"
        )


def create_ai_agent(
    agent_class,
    *,
    config_data: dict | None = None,
    supported_params: set[str] | None = None,
    **agent_kwargs,
):
    """Construct a WebUI-owned Hermes agent with profile routing attached.

    This is the only construction boundary used by WebUI routes and streaming.
    Routing values override caller kwargs so a strict active-profile allowlist
    cannot be weakened by a stale or copied kwargs map.
    """
    agent_kwargs.update(
        provider_routing_agent_kwargs(
            config_data,
            supported_params=supported_params,
            agent_class=agent_class,
        )
    )
    return agent_class(**agent_kwargs)


def _loaded_agent_source_identity() -> tuple[Path, Path] | None:
    """Return the source directory and file that supplied ``run_agent``."""
    module = sys.modules.get("run_agent")
    module_file = getattr(module, "__file__", None)
    if not module_file:
        return None
    try:
        module_path = Path(module_file).resolve()
        return module_path.parent, module_path
    except (OSError, RuntimeError, TypeError):
        return None


def _capture_loaded_agent_revision() -> None:
    """Bind the guard to the checkout that supplied the loaded Agent module."""
    global _AGENT_SOURCE_DIR, _AGENT_MODULE_PATH, _AGENT_REVISION

    if _AGENT_REVISION is not None:
        ensure_agent_runtime_current()
        return

    identity = _loaded_agent_source_identity()
    if identity is None:
        return
    source_dir, module_path = identity
    current_revision = _read_agent_revision(source_dir, module_path=module_path)
    _AGENT_SOURCE_DIR = source_dir
    _AGENT_MODULE_PATH = module_path
    _AGENT_REVISION = current_revision


def ensure_agent_runtime_current() -> None:
    """Reject a known Git checkout change instead of mixing Python modules."""
    if _AGENT_REVISION is None:
        return
    if (
        _read_agent_revision(_AGENT_SOURCE_DIR, module_path=_AGENT_MODULE_PATH)
        != _AGENT_REVISION
    ):
        raise AgentRuntimeChangedError(_RESTART_MESSAGE)


def require_ai_agent_class():
    """Import ``AIAgent`` after proving the loaded source revision is current."""
    ensure_agent_runtime_current()
    from run_agent import AIAgent  # noqa: PLC0415

    _capture_loaded_agent_revision()
    return AIAgent


def get_ai_agent_class():
    """Return ``AIAgent`` while preserving the existing lazy-import retry."""
    global _AIAgent, _AGENT_REVISION

    with _RUNTIME_LOCK:
        ensure_agent_runtime_current()
        if _AIAgent is None:
            try:
                agent_class = require_ai_agent_class()
            except ImportError:
                return None
            _AIAgent = agent_class
        return _AIAgent
