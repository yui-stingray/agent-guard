"""Where: src/agent_guard/surface_inventory.py
What: compatibility facade for repo-local agent surface inventory helpers.
Why: preserve public imports while scanner-specific logic lives in focused modules.
"""

from __future__ import annotations

from .surface_inventory_context import (
    collect_agent_surface_inventory,
    public_safe_surface_text,
    summarize_surfaces,
)
from .surface_inventory_core import (
    AGENT_SURFACE_SCHEMA_VERSION,
    AGENT_SURFACE_SCHEMA_VERSION_V1,
    AGENT_SURFACE_SCHEMA_VERSION_V2,
    SurfaceVersion,
    normalize_surface_version,
    parse_agent_guard_command,
    rel_path,
    safe_metadata_path,
    schema_for_surface_version,
)
from .surface_inventory_directories import (
    AGENT_COMMAND_DIRS,
    AGENT_HOOK_FILES,
    AGENT_PROFILE_DIRS,
    AGENT_SKILL_DIRS,
    MAX_SURFACE_TREE_FILES,
    collect_directory_surfaces,
    collect_hook_surfaces,
    count_tree_files,
)
from .surface_inventory_mcp import (
    MCP_CONFIG_FILES,
    collect_mcp_config_surfaces,
    contains_inline_authorization_arg,
    contains_inline_authorization_url_value,
    contains_inline_authorization_value,
    has_broad_authorization_scope,
    is_scope_field_name,
    iter_mcp_config_files,
    load_structured_config,
    mcp_server_maps,
    scope_values,
)
from .surface_inventory_mcp_safety import (
    AUTH_FIELD_NAMES,
    AUTH_OPTION_RE,
    BROAD_AUTHORIZATION_SCOPE_VALUES,
    MCP_URL_KEYS,
    PACKAGE_MANAGER_COMMANDS,
    SAFE_MCP_URL_SCHEMES,
    SCOPE_FIELD_NAMES,
    SECRET_SHAPED_VALUE,
    command_basename,
    command_inline_args,
    contains_env_reference,
    contains_filesystem_root,
    extract_remote_host,
    has_unsafe_mcp_url_scheme,
    infer_transport,
    infer_version_pin,
    is_authorization_field_name,
    is_env_reference,
    is_inline_auth_literal,
    normalized_auth_field_name,
    safe_mcp_command_basename,
    safe_mcp_env_var_name,
    safe_mcp_public_token,
    safe_mcp_remote_host,
    safe_mcp_server_name,
    string_list,
    string_values,
    unsafe_mcp_public_token,
)
from .surface_inventory_metadata import (
    DOC_GLOBS,
    collect_committed_evidence_surfaces,
    collect_documented_guard_surfaces,
    collect_policy_surfaces,
    policy_kind,
)
from .surface_inventory_workflow import (
    WORKFLOW_GLOBS,
    collect_workflow_artifact_surfaces,
    collect_workflow_surfaces,
    iter_workflow_files,
    parse_output_artifact,
)
