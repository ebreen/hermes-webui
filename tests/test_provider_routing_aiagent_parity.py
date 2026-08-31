"""Provider-routing parity for every WebUI-created Hermes agent."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

import api.agent_runtime as agent_runtime


REPO = Path(__file__).resolve().parent.parent

ROUTING = {
    "only": ["coreweave", "baseten"],
    "ignore": ["together"],
    "order": ["coreweave", "baseten"],
    "sort": "latency",
    "require_parameters": True,
    "data_collection": "deny",
}

EXPECTED = {
    "providers_allowed": ["coreweave", "baseten"],
    "providers_ignored": ["together"],
    "providers_order": ["coreweave", "baseten"],
    "provider_sort": "latency",
    "provider_require_parameters": True,
    "provider_data_collection": "deny",
}


def _routing_kwargs(*args, **kwargs):
    assert hasattr(agent_runtime, "provider_routing_agent_kwargs"), (
        "WebUI must expose provider_routing_agent_kwargs"
    )
    return agent_runtime.provider_routing_agent_kwargs(*args, **kwargs)


def test_provider_routing_maps_to_aiagent_kwargs():
    assert _routing_kwargs({"provider_routing": ROUTING}) == EXPECTED


@pytest.mark.parametrize(
    "routing",
    [
        [],
        "bad",
        42,
        {"only": 7},
        {"only": "coreweave"},
        {"sort": 3},
        {"require_parameters": "YES"},
        {"data_collection": "everything"},
    ],
)
def test_malformed_provider_routing_fails_closed(routing):
    with pytest.raises(agent_runtime.ProviderRoutingConfigError):
        _routing_kwargs({"provider_routing": routing})


def test_non_dict_config_data_fails_closed():
    with pytest.raises(agent_runtime.ProviderRoutingConfigError):
        _routing_kwargs(["not", "a", "dict"])


def test_absent_provider_routing_returns_empty_kwargs():
    # With no profile-owned snapshot/filter, absent routing yields the all-None
    # neutral map (no egress restriction). This is safe: None means "no
    # allowlist" at the AIAgent level, and it only reaches OpenRouter when the
    # model actually routes there. When create_ai_agent passes supported_params
    # the map is narrowed to the agent's real params.
    assert _routing_kwargs({}) == {
        "providers_allowed": None,
        "providers_ignored": None,
        "providers_order": None,
        "provider_sort": None,
        "provider_require_parameters": False,
        "provider_data_collection": None,
    }
    assert _routing_kwargs({"provider_routing": None}) == {
        "providers_allowed": None,
        "providers_ignored": None,
        "providers_order": None,
        "provider_sort": None,
        "provider_require_parameters": False,
        "provider_data_collection": None,
    }


def test_ager_runtime_missing_policy_param_fails_closed():
    with pytest.raises(agent_runtime.ProviderRoutingConfigError):
        _routing_kwargs(
            {"provider_routing": ROUTING},
            supported_params={"providers_order"},
        )


def test_older_build_without_configured_policy_is_allowed():
    # Only neutral defaults (nothing pinned) -> no attempt to enforce a
    # control, so filtering unsupported optional keys is fine.
    kwargs = _routing_kwargs(
        {"provider_routing": {}},
        supported_params=set(),
    )
    assert kwargs == {}


def test_create_ai_agent_injects_routing_at_the_construction_boundary():
    assert hasattr(agent_runtime, "create_ai_agent"), (
        "WebUI must expose a single create_ai_agent construction boundary"
    )
    captured = {}

    class FakeAgent:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    agent = agent_runtime.create_ai_agent(
        FakeAgent,
        config_data={"provider_routing": ROUTING},
        model="deepseek/deepseek-v4-flash-0731",
        provider="openrouter",
    )

    assert isinstance(agent, FakeAgent)
    assert captured["model"] == "deepseek/deepseek-v4-flash-0731"
    assert captured["provider"] == "openrouter"
    for key, value in EXPECTED.items():
        assert captured[key] == value


def _direct_agent_constructor_lines(path: Path) -> list[int]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"AIAgent", "_AIAgent"}
    ]


def test_no_webui_agent_constructor_bypasses_shared_factory():
    bypasses = {}
    for relative in ("api/routes.py", "api/streaming.py"):
        lines = _direct_agent_constructor_lines(REPO / relative)
        if lines:
            bypasses[relative] = lines
    assert not bypasses, f"direct AIAgent construction bypasses shared factory: {bypasses}"


def test_streaming_cache_identity_includes_provider_routing():
    path = REPO / "api" / "streaming.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    signature_values = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not any(
            isinstance(target, ast.Name) and target.id == "_sig_blob"
            for target in node.targets
        ):
            continue
        signature_values.append(node.value)

    assert signature_values, "expected the streaming agent cache signature"
    assert any(
        isinstance(child, ast.Name) and child.id == "_provider_routing_kwargs"
        for value in signature_values
        for child in ast.walk(value)
    ), "provider routing must be part of the cached agent identity"
