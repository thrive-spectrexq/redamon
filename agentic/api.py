"""
RedAmon Agent WebSocket API

FastAPI application providing WebSocket endpoint for real-time agent communication.
Supports session-based conversation continuity and phase-based approval flow.

Endpoints:
    WS /ws/agent - WebSocket endpoint for real-time bidirectional streaming
    GET /health - Health check
    GET /defaults - Agent default settings (camelCase, for frontend)
    GET /models - Available AI models from all configured providers
"""

import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from logging_config import setup_logging
from orchestrator import AgentOrchestrator
from utils import get_session_count
from websocket_api import WebSocketManager, websocket_endpoint

# Initialize logging with file rotation
setup_logging(log_level=logging.INFO, log_to_console=True, log_to_file=True)
logger = logging.getLogger(__name__)

orchestrator: Optional[AgentOrchestrator] = None
ws_manager: Optional[WebSocketManager] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.

    Initializes the orchestrator and WebSocket manager on startup and cleans up on shutdown.
    """
    global orchestrator, ws_manager

    logger.info("Starting RedAmon Agent API...")

    # Initialize orchestrator
    orchestrator = AgentOrchestrator()
    await orchestrator.initialize()

    # Initialize WebSocket manager
    ws_manager = WebSocketManager()

    logger.info("RedAmon Agent API ready (WebSocket)")

    yield

    logger.info("Shutting down RedAmon Agent API...")
    if orchestrator:
        await orchestrator.close()


app = FastAPI(
    title="RedAmon Agent API",
    description="WebSocket API for real-time agent communication with phase tracking, MCP tools, and Neo4j integration",
    version="3.0.0",
    lifespan=lifespan
)

# Add CORS middleware for webapp (allow all origins for development)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,  # Must be False when allow_origins is ["*"]
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# RESPONSE MODELS (for /health endpoint only)
# =============================================================================

class HealthResponse(BaseModel):
    """Response model for health check."""
    status: str
    version: str
    tools_loaded: int
    active_sessions: int


# =============================================================================
# ENDPOINTS
# =============================================================================


@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health():
    """
    Health check endpoint.

    Returns the API status, version, number of loaded tools, and active sessions.
    """
    tools_count = 0
    if orchestrator and orchestrator.tool_executor:
        tools_count = len(orchestrator.tool_executor.get_all_tools())

    sessions_count = get_session_count()

    return HealthResponse(
        status="ok" if orchestrator and orchestrator._initialized else "initializing",
        version="3.0.0",
        tools_loaded=tools_count,
        active_sessions=sessions_count
    )


@app.get("/defaults", tags=["System"])
async def get_defaults():
    """
    Get default agent settings for frontend project creation.

    Returns DEFAULT_AGENT_SETTINGS with camelCase keys prefixed with 'agent'
    for frontend compatibility (e.g., OPENAI_MODEL -> agentOpenaiModel).
    """
    from project_settings import DEFAULT_AGENT_SETTINGS

    def to_camel_case(snake_str: str, prefix: str = "agent") -> str:
        """Convert SCREAMING_SNAKE_CASE to prefixCamelCase."""
        prefixed = f"{prefix}_{snake_str}" if prefix else snake_str
        components = prefixed.lower().split('_')
        return components[0] + ''.join(x.title() for x in components[1:])

    # STEALTH_MODE is a project-level setting (not agent-specific), served by
    # recon defaults as "stealthMode".  Exclude it here to avoid creating a
    # duplicate "agentStealthMode" key that Prisma doesn't recognise.
    SKIP_KEYS = {'STEALTH_MODE'}

    # HYDRA_* keys map to Prisma fields without the 'agent' prefix
    # (e.g. HYDRA_ENABLED -> hydraEnabled, not agentHydraEnabled)
    NO_PREFIX_KEYS = {k for k in DEFAULT_AGENT_SETTINGS if k.startswith('HYDRA_')}

    camel_case_defaults = {}
    for k, v in DEFAULT_AGENT_SETTINGS.items():
        if k in SKIP_KEYS:
            continue
        if k in NO_PREFIX_KEYS:
            camel_case_defaults[to_camel_case(k, prefix="")] = v
        else:
            camel_case_defaults[to_camel_case(k)] = v

    return camel_case_defaults


@app.get("/models", tags=["System"])
async def get_models():
    """
    Fetch available AI models from all configured providers.

    Returns a dict keyed by provider name, each containing a list of models
    with {id, name, context_length, description}. Results are cached for 1 hour.
    Only providers with valid API keys in the environment are queried.
    """
    from model_providers import fetch_all_models
    return await fetch_all_models()


@app.websocket("/ws/agent")
async def agent_websocket(websocket: WebSocket):
    """
    WebSocket endpoint for real-time agent communication.

    Provides bidirectional streaming of:
    - LLM thinking process
    - Tool executions and outputs
    - Phase transitions
    - Approval requests
    - Agent questions
    - Todo list updates

    The client must send an 'init' message first to authenticate the session.
    """
    if not orchestrator:
        await websocket.close(code=1011, reason="Orchestrator not initialized")
        return

    if not ws_manager:
        await websocket.close(code=1011, reason="WebSocket manager not initialized")
        return

    await websocket_endpoint(websocket, orchestrator, ws_manager)
