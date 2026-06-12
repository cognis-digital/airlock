"""airlock — declarative air-gapped software delivery. Part of the Cognis Neural Suite."""

from airlock.core import (
    TOOL_NAME,
    TOOL_VERSION,
    AirlockError,
    Artifact,
    BUNDLE_FORMAT,
    create_bundle,
    deploy_bundle,
    draft_manifest,
    inspect_bundle,
    load_manifest,
    merkle_root,
    parse_yaml_subset,
    plan_deploy,
    resolve_artifacts,
    sha256_bytes,
    sha256_file,
    verify_bundle,
)

__version__ = TOOL_VERSION

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "__version__",
    "AirlockError",
    "Artifact",
    "BUNDLE_FORMAT",
    "create_bundle",
    "deploy_bundle",
    "draft_manifest",
    "inspect_bundle",
    "load_manifest",
    "merkle_root",
    "parse_yaml_subset",
    "plan_deploy",
    "resolve_artifacts",
    "sha256_bytes",
    "sha256_file",
    "verify_bundle",
]
