"""
Agent Project Settings - Fetch agent configuration from webapp API

When PROJECT_ID and WEBAPP_API_URL are set as environment variables,
settings are fetched from the PostgreSQL database via webapp API.
Otherwise, falls back to DEFAULT_AGENT_SETTINGS for standalone usage.

Mirrors the pattern from recon/project_settings.py.
"""
import os
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

# =============================================================================
# DEFAULT SETTINGS - Used as fallback for standalone usage and missing API fields
# =============================================================================

DEFAULT_AGENT_SETTINGS: dict[str, Any] = {
    # LLM Configuration
    'OPENAI_MODEL': 'gpt-5.2',
    'INFORMATIONAL_SYSTEM_PROMPT': '',
    'EXPL_SYSTEM_PROMPT': '',
    'POST_EXPL_SYSTEM_PROMPT': '',

    # Phase Configuration
    'ACTIVATE_POST_EXPL_PHASE': True,
    'POST_EXPL_PHASE_TYPE': 'statefull',

    # Payload Direction
    'LHOST': '',       # Empty string = not set (bind payload mode)
    'LPORT': None,      # None = not set (bind payload mode)
    'BIND_PORT_ON_TARGET': 4444,
    'PAYLOAD_USE_HTTPS': False,

    # Agent Limits
    'MAX_ITERATIONS': 100,
    'EXECUTION_TRACE_MEMORY_STEPS': 100,
    'TOOL_OUTPUT_MAX_CHARS': 8000,

    # Approval Gates
    'REQUIRE_APPROVAL_FOR_EXPLOITATION': True,
    'REQUIRE_APPROVAL_FOR_POST_EXPLOITATION': True,

    # Neo4j
    'CYPHER_MAX_RETRIES': 3,

    # Debug
    'CREATE_GRAPH_IMAGE_ON_INIT': False,

    # Logging
    'LOG_MAX_MB': 10,
    'LOG_BACKUP_COUNT': 5,

    # Tool Phase Restrictions
    'TOOL_PHASE_MAP': {
        'query_graph': ['informational', 'exploitation', 'post_exploitation'],
        'execute_curl': ['informational', 'exploitation', 'post_exploitation'],
        'execute_naabu': ['informational', 'exploitation', 'post_exploitation'],
        'metasploit_console': ['exploitation', 'post_exploitation'],
        'msf_restart': ['exploitation', 'post_exploitation'],
    },

    # Brute Force
    'BRUTE_FORCE_MAX_WORDLIST_ATTEMPTS': 3,
}


def fetch_agent_settings(project_id: str, webapp_url: str) -> dict[str, Any]:
    """
    Fetch agent settings from webapp API.

    Args:
        project_id: The project ID to fetch settings for
        webapp_url: Base URL of the webapp API (e.g., http://localhost:3000)

    Returns:
        Dictionary of settings in SCREAMING_SNAKE_CASE format
    """
    import requests

    url = f"{webapp_url.rstrip('/')}/api/projects/{project_id}"
    logger.info(f"Fetching agent settings from {url}")

    response = requests.get(url, timeout=30)
    response.raise_for_status()
    project = response.json()

    # Start with defaults, then override with API values
    settings = DEFAULT_AGENT_SETTINGS.copy()

    # Map camelCase API fields to SCREAMING_SNAKE_CASE
    settings['OPENAI_MODEL'] = project.get('agentOpenaiModel', DEFAULT_AGENT_SETTINGS['OPENAI_MODEL'])
    settings['INFORMATIONAL_SYSTEM_PROMPT'] = project.get('agentInformationalSystemPrompt', DEFAULT_AGENT_SETTINGS['INFORMATIONAL_SYSTEM_PROMPT'])
    settings['EXPL_SYSTEM_PROMPT'] = project.get('agentExplSystemPrompt', DEFAULT_AGENT_SETTINGS['EXPL_SYSTEM_PROMPT'])
    settings['POST_EXPL_SYSTEM_PROMPT'] = project.get('agentPostExplSystemPrompt', DEFAULT_AGENT_SETTINGS['POST_EXPL_SYSTEM_PROMPT'])
    settings['ACTIVATE_POST_EXPL_PHASE'] = project.get('agentActivatePostExplPhase', DEFAULT_AGENT_SETTINGS['ACTIVATE_POST_EXPL_PHASE'])
    settings['POST_EXPL_PHASE_TYPE'] = project.get('agentPostExplPhaseType', DEFAULT_AGENT_SETTINGS['POST_EXPL_PHASE_TYPE'])
    settings['LHOST'] = project.get('agentLhost', DEFAULT_AGENT_SETTINGS['LHOST'])
    settings['LPORT'] = project.get('agentLport', DEFAULT_AGENT_SETTINGS['LPORT'])
    settings['BIND_PORT_ON_TARGET'] = project.get('agentBindPortOnTarget', DEFAULT_AGENT_SETTINGS['BIND_PORT_ON_TARGET'])
    settings['PAYLOAD_USE_HTTPS'] = project.get('agentPayloadUseHttps', DEFAULT_AGENT_SETTINGS['PAYLOAD_USE_HTTPS'])
    settings['MAX_ITERATIONS'] = project.get('agentMaxIterations', DEFAULT_AGENT_SETTINGS['MAX_ITERATIONS'])
    settings['EXECUTION_TRACE_MEMORY_STEPS'] = project.get('agentExecutionTraceMemorySteps', DEFAULT_AGENT_SETTINGS['EXECUTION_TRACE_MEMORY_STEPS'])
    settings['REQUIRE_APPROVAL_FOR_EXPLOITATION'] = project.get('agentRequireApprovalForExploitation', DEFAULT_AGENT_SETTINGS['REQUIRE_APPROVAL_FOR_EXPLOITATION'])
    settings['REQUIRE_APPROVAL_FOR_POST_EXPLOITATION'] = project.get('agentRequireApprovalForPostExploitation', DEFAULT_AGENT_SETTINGS['REQUIRE_APPROVAL_FOR_POST_EXPLOITATION'])
    settings['TOOL_OUTPUT_MAX_CHARS'] = project.get('agentToolOutputMaxChars', DEFAULT_AGENT_SETTINGS['TOOL_OUTPUT_MAX_CHARS'])
    settings['CYPHER_MAX_RETRIES'] = project.get('agentCypherMaxRetries', DEFAULT_AGENT_SETTINGS['CYPHER_MAX_RETRIES'])
    settings['CREATE_GRAPH_IMAGE_ON_INIT'] = project.get('agentCreateGraphImageOnInit', DEFAULT_AGENT_SETTINGS['CREATE_GRAPH_IMAGE_ON_INIT'])
    settings['LOG_MAX_MB'] = project.get('agentLogMaxMb', DEFAULT_AGENT_SETTINGS['LOG_MAX_MB'])
    settings['LOG_BACKUP_COUNT'] = project.get('agentLogBackupCount', DEFAULT_AGENT_SETTINGS['LOG_BACKUP_COUNT'])
    settings['TOOL_PHASE_MAP'] = project.get('agentToolPhaseMap', DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP'])
    settings['BRUTE_FORCE_MAX_WORDLIST_ATTEMPTS'] = project.get('agentBruteForceMaxWordlistAttempts', DEFAULT_AGENT_SETTINGS['BRUTE_FORCE_MAX_WORDLIST_ATTEMPTS'])

    logger.info(f"Loaded {len(settings)} agent settings for project {project_id}")
    return settings


def get_settings() -> dict[str, Any]:
    """
    Get agent settings from webapp API.

    REQUIRES PROJECT_ID and WEBAPP_API_URL environment variables to be set.
    Falls back to DEFAULT_AGENT_SETTINGS only for standalone usage without env vars.

    Returns:
        Dictionary of settings in SCREAMING_SNAKE_CASE format
    """
    project_id = os.environ.get('PROJECT_ID')
    webapp_url = os.environ.get('WEBAPP_API_URL')

    if project_id and webapp_url:
        try:
            settings = fetch_agent_settings(project_id, webapp_url)
            logger.info(f"Loaded {len(settings)} agent settings from API for project {project_id}")
            return settings

        except Exception as e:
            logger.error(f"Failed to fetch agent settings: {e}")
            logger.warning("Falling back to DEFAULT_AGENT_SETTINGS")
            return DEFAULT_AGENT_SETTINGS.copy()

    # Fallback to DEFAULT_AGENT_SETTINGS for standalone usage
    logger.info("Using DEFAULT_AGENT_SETTINGS (no PROJECT_ID/WEBAPP_API_URL set)")
    return DEFAULT_AGENT_SETTINGS.copy()


# Singleton settings instance
_settings: Optional[dict[str, Any]] = None


def get_setting(key: str, default: Any = None) -> Any:
    """
    Get a single agent setting value.

    Args:
        key: Setting name in SCREAMING_SNAKE_CASE
        default: Default value if setting not found

    Returns:
        Setting value or default
    """
    global _settings
    if _settings is None:
        _settings = get_settings()
    return _settings.get(key, default)


def reload_settings() -> dict[str, Any]:
    """Force reload of settings (useful for testing)"""
    global _settings
    _settings = get_settings()
    return _settings


# =============================================================================
# TOOL PHASE RESTRICTION HELPERS (moved from params.py)
# =============================================================================

def is_tool_allowed_in_phase(tool_name: str, phase: str) -> bool:
    """Check if a tool is allowed in the given phase."""
    tool_phase_map = get_setting('TOOL_PHASE_MAP', {})
    allowed_phases = tool_phase_map.get(tool_name, [])
    return phase in allowed_phases


def get_allowed_tools_for_phase(phase: str) -> list:
    """Get list of tool names allowed in the given phase."""
    tool_phase_map = get_setting('TOOL_PHASE_MAP', {})
    return [
        tool_name
        for tool_name, allowed_phases in tool_phase_map.items()
        if phase in allowed_phases
    ]
