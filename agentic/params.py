"""
RedAmon Agent Parameters

Configuration constants for the agent orchestrator.
"""

OPENAI_MODEL = "gpt-4.1"
MCP_CURL_URL = "http://host.docker.internal:8001/sse"

CREATE_GRAPH_IMAGRE_ON_INIT = True

# Cypher query retry settings
CYPHER_MAX_RETRIES = 3  # Maximum number of retry attempts for failed Cypher queries
