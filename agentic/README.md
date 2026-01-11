# RedAmon Agent Orchestrator

LangGraph-based AI agent for penetration testing reconnaissance with MCP tools and Neo4j integration.

## Overview

This module provides a REST API for interacting with an AI agent that can:
- Execute HTTP requests via curl (MCP tool)
- Query the Neo4j graph database using natural language (text-to-Cypher)
- Maintain conversation context across sessions (via LangGraph MemorySaver)

## Architecture

```
User Question (REST API)
      │
      ▼
┌─────────────────────────────────────────┐
│         AgentOrchestrator               │
│  ┌─────────────────────────────────┐    │
│  │      LangGraph StateGraph       │    │
│  │                                 │    │
│  │  START → agent → tools → END    │    │
│  └─────────────────────────────────┘    │
│                  │                      │
│    ┌─────────────┴─────────────┐        │
│    ▼                           ▼        │
│  MCP Tools                  Neo4j       │
│  (curl)                 (text2cypher)   │
└─────────────────────────────────────────┘
      │                           │
      ▼                           ▼
┌──────────────┐          ┌─────────────┐
│ Kali Sandbox │          │   Neo4j     │
│  :8001/sse   │          │   :7687     │
└──────────────┘          └─────────────┘
```

## Files

| File | Description |
|------|-------------|
| `state.py` | LangGraph state type definitions (AgentState) |
| `utils.py` | Utility functions (config, session helpers) |
| `prompts.py` | System prompts for tool selection |
| `orchestrator.py` | Main AgentOrchestrator class with MemorySaver checkpointer |
| `api.py` | FastAPI REST endpoints |
| `requirements.txt` | Python dependencies |
| `Dockerfile` | Container configuration |
| `docker-compose.yml` | Service orchestration |

## Quick Start

### Prerequisites

1. **MCP servers running** (from `mcp/` folder):
   ```bash
   cd ../mcp && docker-compose up -d
   ```

2. **Neo4j running** (from `graph_db/` folder):
   ```bash
   cd ../graph_db && docker-compose up -d
   ```

3. **Environment variables** in `.env`:
   ```
   OPENAI_API_KEY=sk-...
   NEO4J_USER=neo4j
   NEO4J_PASSWORD=your_password
   ```

### Run with Docker

```bash
# Build and start the agent, also after python code change
docker-compose up --build

# View logs
docker-compose logs -f agent
```

### To refresh after code changes
```bash
docker-compose down && docker-compose up --build
```


## API Reference

### POST /query

Send a question to the agent.

### GET /health

Health check endpoint.

## Usage Examples

### Basic curl request

```bash
curl -X POST http://localhost:8090/query \
  -H "Content-Type: application/json" \
  -d '{
    "question": "Use curl to get the headers from https://www.devergolabs.com",
    "user_id": "user1",
    "project_id": "pentest1",
    "session_id": "session-001"
  }'
```

### Query graph database

```bash
curl -X POST http://localhost:8090/query \
  -H "Content-Type: application/json" \
  -d '{
    "question": "List me all the vulnerabilityes you find in the system and explain me how to mitigate each one.",
    "user_id": "user1",
    "project_id": "pentest1",
    "session_id": "session-002"
  }'
```

### Follow-up question (same session)

```bash
curl -X POST http://localhost:8090/query \
  -H "Content-Type: application/json" \
  -d '{
    "question": "What was the status code from that request?",
    "user_id": "user1",
    "project_id": "pentest1",
    "session_id": "session-001"
  }'
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENAI_API_KEY` | OpenAI API key | Required |
| `OPENAI_MODEL` | Model to use | `gpt-4.1` |
| `NEO4J_URI` | Neo4j Bolt URI | `bolt://localhost:7687` |
| `NEO4J_USER` | Neo4j username | `neo4j` |
| `NEO4J_PASSWORD` | Neo4j password | Required |
| `MCP_CURL_URL` | MCP curl server URL | `http://localhost:8001/sse` |

### Docker Network

The agent connects to:
- **Neo4j**: via `host.docker.internal:7687` (host machine)
- **MCP servers**: via `redamon-kali:8001` (Docker network)

Ensure the `redamon-net` network exists:
```bash
docker network create redamon-net
```

## Tools Available

### 1. execute_curl
Make HTTP requests using curl. The LLM constructs the appropriate curl command.

**Examples:**
- Check if a site is up
- Get HTTP headers
- Test API endpoints
- Send POST requests

### 2. query_graph
Query the Neo4j graph database using natural language. Converts questions to Cypher queries.

**Available data:**
- Domains, Subdomains, IPs
- Ports, Services
- Technologies (with versions)
- Vulnerabilities (CVEs)
- Endpoints, Parameters

## Session Management

Sessions are managed by LangGraph's **MemorySaver** checkpointer and persist until:
- The container restarts

Each session maintains full conversation history, allowing follow-up questions.

**Thread ID format:** `{user_id}:{project_id}:{session_id}`

## Project Structure

```
agentic/
├── api.py              # FastAPI application
├── orchestrator.py     # AgentOrchestrator class + MemorySaver checkpointer
├── state.py            # LangGraph state type definitions
├── utils.py            # Utility functions (config, session helpers)
├── prompts.py          # System prompts
├── requirements.txt    # Dependencies
├── Dockerfile          # Container build
├── docker-compose.yml  # Service orchestration
├── .env                # Environment variables
└── README.md           # This file
```

## Adding New Tools

1. Add MCP server to `mcp/servers/`
2. Update `orchestrator.py` to connect to new server
3. Update prompts in `prompts.py` to describe the new tool

## Troubleshooting

### MCP connection failed

Ensure the Kali sandbox is running:
```bash
cd ../mcp && docker-compose ps
```

### Neo4j connection failed

Ensure Neo4j is running and accessible:
```bash
curl http://localhost:7474  # Should return Neo4j info
```

### Network issues in Docker

Check the network exists:
```bash
docker network ls | grep redamon-net
```

Create if missing:
```bash
docker network create redamon-net
```
