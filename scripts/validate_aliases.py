"""Cross-validate Policy Bundle Model Aliases against Model Router config.yaml."""

from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path

import yaml

from platform_common import load_policy_bundle

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_POLICY_PATH = REPO_ROOT / "policies" / "policy-bundle.yaml"
DEFAULT_ROUTER_CONFIG_PATH = REPO_ROOT / "services" / "litellm-proxy" / "config.yaml"


class AliasValidationError(ValueError):
    """Raised when a Policy Bundle references a Model Alias missing from the Model Router."""


def _load_router_model_aliases(router_config_path: Path) -> set[str]:
    if not router_config_path.exists():
        raise FileNotFoundError(f"Model Router config not found: {router_config_path}")

    parsed = yaml.safe_load(router_config_path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise AliasValidationError(
            f"Model Router config at {router_config_path} must be a YAML mapping"
        )

    model_list = parsed.get("model_list")
    if not isinstance(model_list, list):
        raise AliasValidationError(
            f"Model Router config at {router_config_path} must define a 'model_list' list"
        )

    aliases: set[str] = set()
    for index, entry in enumerate(model_list):
        if not isinstance(entry, dict):
            raise AliasValidationError(
                f"Model Router model_list[{index}] in {router_config_path} must be a mapping"
            )
        model_name = entry.get("model_name")
        if not isinstance(model_name, str) or not model_name.strip():
            raise AliasValidationError(
                f"Model Router model_list[{index}] in {router_config_path} is missing 'model_name'"
            )
        aliases.add(model_name.strip())

    return aliases


def validate_policy_and_router_aliases(
    policy_path: str | Path = DEFAULT_POLICY_PATH,
    router_config_path: str | Path = DEFAULT_ROUTER_CONFIG_PATH,
) -> list[str]:
    """Ensure every Policy Bundle Model Alias resolves to an entry in Model Router model_list."""
    loaded_policy = load_policy_bundle(policy_path)
    router_aliases = _load_router_model_aliases(Path(router_config_path))

    required_sources: dict[str, list[str]] = defaultdict(list)
    for alias in loaded_policy.bundle.models:
        required_sources[alias].append("policy.models")

    for team_name, team_policy in loaded_policy.bundle.teams.items():
        for alias in team_policy.allowed_model_aliases:
            effective_alias = team_policy.model_alias_remapping.get(alias, alias)
            source = (
                f"teams.{team_name}.allowed_model_aliases({alias}->{effective_alias})"
                if effective_alias != alias
                else f"teams.{team_name}.allowed_model_aliases"
            )
            required_sources[effective_alias].append(source)

    missing = {
        alias: sources
        for alias, sources in sorted(required_sources.items())
        if alias not in router_aliases
    }
    if missing:
        details = ", ".join(
            f"{alias} (from {'; '.join(sources)})" for alias, sources in missing.items()
        )
        raise AliasValidationError(
            f"Model Alias drift detected; missing from Model Router model_list: {details}"
        )

    return sorted(required_sources)


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint for validating Policy Bundle and Model Router Model Aliases."""
    parser = argparse.ArgumentParser(
        description="Validate Policy Bundle Model Aliases against LiteLLM Proxy model_list."
    )
    parser.add_argument(
        "--policy",
        type=Path,
        default=DEFAULT_POLICY_PATH,
        help="Path to the Control Plane Policy Bundle YAML file.",
    )
    parser.add_argument(
        "--router-config",
        type=Path,
        default=DEFAULT_ROUTER_CONFIG_PATH,
        help="Path to the Model Router (LiteLLM Proxy) config.yaml file.",
    )
    args = parser.parse_args(argv)

    try:
        validated = validate_policy_and_router_aliases(args.policy, args.router_config)
    except (AliasValidationError, ValueError, FileNotFoundError, yaml.YAMLError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(
        f"Validated {len(validated)} Model Alias(es) between {args.policy} and "
        f"{args.router_config}: {', '.join(validated)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
