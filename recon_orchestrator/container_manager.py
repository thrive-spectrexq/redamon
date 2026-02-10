"""
Docker container lifecycle management for recon processes
"""
import asyncio
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncGenerator, Optional

import docker
from docker.errors import NotFound, APIError
from docker.models.containers import Container

from models import ReconState, ReconStatus, ReconLogEvent

logger = logging.getLogger(__name__)

# ANSI escape code pattern for stripping terminal colors from logs
ANSI_ESCAPE = re.compile(r'\x1b\[[0-9;]*m|\033\[[0-9;]*m')

# Sub-container images spawned by recon (Docker-in-Docker sibling containers)
SUB_CONTAINER_IMAGES = [
    "projectdiscovery/naabu",
    "projectdiscovery/httpx",
    "projectdiscovery/katana",
    "projectdiscovery/nuclei",
    "sxcurity/gau",
]

# Phase patterns to detect from logs
# Order matters - more specific patterns should come first within each phase
PHASE_PATTERNS = [
    (r"\[Phase 1\]|\[PHASE 1\]|Phase 1:|WHOIS Lookup|domain.*discovery|Domain Reconnaissance", "Domain Discovery", 1),
    (r"\[Phase 2\]|\[PHASE 2\]|Phase 2:|NAABU PORT SCANNER|port.*scan", "Port Scanning", 2),
    (r"\[Phase 3\]|\[PHASE 3\]|Phase 3:|HTTPX HTTP PROBER|http.*prob", "HTTP Probing", 3),
    (r"\[Phase 4\]|\[PHASE 4\]|Phase 4:|Resource Enumeration|Katana.*GAU|resource.*enum", "Resource Enumeration", 4),
    (r"\[Phase 5\]|\[PHASE 5\]|Phase 5:|NUCLEI|Vulnerability Scan|vuln.*scan", "Vulnerability Scanning", 5),
    (r"\[Phase 6\]|\[PHASE 6\]|Phase 6:|CVE LOOKUP|MITRE|CWE|CAPEC", "CVE & MITRE", 6),
    (r"\[Phase 7\]|\[PHASE 7\]|Phase 7:|GitHub Secret|github.*secret", "GitHub Secret Hunt", 7),
]


class ContainerManager:
    """Manages Docker containers for recon processes"""

    def __init__(self, recon_image: str = "redamon-recon:latest"):
        self.client = docker.from_env()
        self.recon_image = recon_image
        self.running_states: dict[str, ReconState] = {}
        self._log_tasks: dict[str, asyncio.Task] = {}

    def _get_container_name(self, project_id: str) -> str:
        """Generate container name for a project"""
        # Sanitize project_id for container name
        safe_id = re.sub(r'[^a-zA-Z0-9_.-]', '_', project_id)
        return f"redamon-recon-{safe_id}"

    async def get_status(self, project_id: str) -> ReconState:
        """Get current status of a recon process"""
        if project_id in self.running_states:
            state = self.running_states[project_id]

            # Check if container is still running
            if state.container_id:
                try:
                    container = self.client.containers.get(state.container_id)
                    if container.status != "running":
                        # Container stopped - check exit code
                        exit_code = container.attrs.get("State", {}).get("ExitCode", -1)
                        if exit_code == 0:
                            state.status = ReconStatus.COMPLETED
                            state.completed_at = datetime.now(timezone.utc)
                        else:
                            state.status = ReconStatus.ERROR
                            state.error = f"Container exited with code {exit_code}"
                            state.completed_at = datetime.now(timezone.utc)

                        # Auto-cleanup: remove finished container
                        try:
                            container.remove()
                            logger.info(f"Auto-removed finished container for project {project_id}")
                        except Exception as e:
                            logger.warning(f"Failed to auto-remove container: {e}")
                except NotFound:
                    # Only set error if not already in a terminal state
                    # (container may have been auto-removed after completion)
                    if state.status not in (ReconStatus.COMPLETED, ReconStatus.ERROR):
                        state.status = ReconStatus.ERROR
                        state.error = "Container not found"

            return state

        # Check if there's an orphan container
        container_name = self._get_container_name(project_id)
        try:
            container = self.client.containers.get(container_name)
            if container.status == "running":
                return ReconState(
                    project_id=project_id,
                    status=ReconStatus.RUNNING,
                    container_id=container.id,
                )
        except NotFound:
            pass

        return ReconState(
            project_id=project_id,
            status=ReconStatus.IDLE,
        )

    async def start_recon(
        self,
        project_id: str,
        user_id: str,
        webapp_api_url: str,
        recon_path: str = "/home/samuele/Progetti didattici/RedAmon/recon",
    ) -> ReconState:
        """Start a recon container for a project"""

        # Check if already running
        current_state = await self.get_status(project_id)
        if current_state.status == ReconStatus.RUNNING:
            raise ValueError(f"Recon already running for project {project_id}")

        # Clean up any existing container
        container_name = self._get_container_name(project_id)
        try:
            old_container = self.client.containers.get(container_name)
            old_container.remove(force=True)
            logger.info(f"Removed old container {container_name}")
        except NotFound:
            pass

        # Create new state
        state = ReconState(
            project_id=project_id,
            status=ReconStatus.STARTING,
            started_at=datetime.now(timezone.utc),
        )
        self.running_states[project_id] = state

        try:
            # Ensure recon image exists
            try:
                self.client.images.get(self.recon_image)
            except NotFound:
                logger.info(f"Building recon image from {recon_path}")
                self.client.images.build(
                    path=recon_path,
                    tag=self.recon_image,
                    rm=True,
                )

            # Start container with environment variables
            container = self.client.containers.run(
                self.recon_image,
                name=container_name,
                detach=True,
                network_mode="host",
                cap_add=["NET_RAW", "NET_ADMIN"],
                environment={
                    "PROJECT_ID": project_id,
                    "USER_ID": user_id,
                    "WEBAPP_API_URL": webapp_api_url,
                    "UPDATE_GRAPH_DB": "true",
                    # HOST_RECON_OUTPUT_PATH: Required for nested Docker containers (naabu, httpx, etc.)
                    # These run as sibling containers and need host paths for volume mounts
                    "HOST_RECON_OUTPUT_PATH": f"{recon_path}/output",
                    # Forward credentials from orchestrator environment
                    "NVD_API_KEY": os.environ.get("NVD_API_KEY", ""),
                    "NEO4J_URI": os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
                    "NEO4J_USER": os.environ.get("NEO4J_USER", "neo4j"),
                    "NEO4J_PASSWORD": os.environ.get("NEO4J_PASSWORD", ""),
                },
                volumes={
                    "/var/run/docker.sock": {"bind": "/var/run/docker.sock", "mode": "ro"},
                    # Mount source code for development (no rebuild needed)
                    # Note: rw needed because output/data are subdirectories
                    f"{recon_path}": {"bind": "/app/recon", "mode": "rw"},
                    # Mount graph_db module
                    f"{Path(recon_path).parent}/graph_db": {"bind": "/app/graph_db", "mode": "ro"},
                    # Mount /tmp for Docker-in-Docker temp files (avoids spaces in paths)
                    "/tmp/redamon": {"bind": "/tmp/redamon", "mode": "rw"},
                },
                command="python /app/recon/main.py",
            )

            state.container_id = container.id
            state.status = ReconStatus.RUNNING
            logger.info(f"Started recon container {container.id} for project {project_id}")

        except Exception as e:
            state.status = ReconStatus.ERROR
            state.error = str(e)
            logger.error(f"Failed to start recon for {project_id}: {e}")

        return state

    def _cleanup_sub_containers(self) -> int:
        """Stop and remove any running sub-containers (naabu, httpx, nuclei, etc.)

        Returns the count of containers cleaned up.
        """
        cleaned = 0
        try:
            # Find all running containers
            containers = self.client.containers.list(all=True)
            for container in containers:
                try:
                    # Check if container image matches any sub-container image
                    image_tags = container.image.tags if container.image.tags else []
                    image_name = container.attrs.get("Config", {}).get("Image", "")

                    for sub_image in SUB_CONTAINER_IMAGES:
                        # Match by image name or tags
                        if (sub_image in image_name or
                            any(sub_image in tag for tag in image_tags)):
                            container_name = container.name
                            container_status = container.status

                            # Stop if running
                            if container_status == "running":
                                logger.info(f"Stopping sub-container: {container_name} ({sub_image})")
                                container.stop(timeout=5)

                            # Remove container
                            logger.info(f"Removing sub-container: {container_name} ({sub_image})")
                            container.remove(force=True)
                            cleaned += 1
                            break

                except Exception as e:
                    logger.warning(f"Error cleaning up container {container.name}: {e}")

        except Exception as e:
            logger.error(f"Error listing containers for cleanup: {e}")

        return cleaned

    async def stop_recon(self, project_id: str, timeout: int = 10) -> ReconState:
        """Stop a running recon process"""
        state = await self.get_status(project_id)

        if state.status != ReconStatus.RUNNING:
            return state

        state.status = ReconStatus.STOPPING

        if state.container_id:
            try:
                container = self.client.containers.get(state.container_id)
                container.stop(timeout=timeout)
                container.remove()
                state.status = ReconStatus.IDLE
                state.completed_at = datetime.now(timezone.utc)
                logger.info(f"Stopped recon container for project {project_id}")
            except NotFound:
                state.status = ReconStatus.IDLE
            except Exception as e:
                state.status = ReconStatus.ERROR
                state.error = f"Failed to stop: {e}"

        # Clean up any sub-containers (naabu, httpx, nuclei, etc.)
        cleaned = self._cleanup_sub_containers()
        if cleaned > 0:
            logger.info(f"Cleaned up {cleaned} sub-container(s) for project {project_id}")

        # Clean up state
        if project_id in self.running_states:
            del self.running_states[project_id]

        return state

    def _parse_log_line(self, line: str, current_phase: Optional[str], current_phase_num: Optional[int], timestamp: Optional[datetime] = None) -> ReconLogEvent:
        """Parse a log line and detect phase changes"""
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)
        phase = current_phase
        phase_num = current_phase_num
        is_phase_start = False
        level = "info"

        # Strip ANSI escape codes (terminal colors) from log line
        line = ANSI_ESCAPE.sub('', line)

        # Detect log level based on prefix symbols only
        # [!] = error (red), [+]/[✓] = success (green), [*] = action (blue), no symbol = info (gray)
        if "[!]" in line:
            level = "error"  # Red
        elif "[+]" in line or "[✓]" in line:
            level = "success"  # Green
        elif "[*]" in line:
            level = "action"  # Blue

        # Detect phase changes
        for pattern, phase_name, num in PHASE_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                if phase_name != current_phase:
                    phase = phase_name
                    phase_num = num
                    is_phase_start = True
                break

        return ReconLogEvent(
            log=line.strip(),
            timestamp=timestamp,
            phase=phase,
            phase_number=phase_num,
            is_phase_start=is_phase_start,
            level=level,
        )

    async def stream_logs(self, project_id: str) -> AsyncGenerator[ReconLogEvent, None]:
        """Stream logs from a recon container"""
        state = await self.get_status(project_id)

        if not state.container_id:
            yield ReconLogEvent(
                log="No container found for this project",
                timestamp=datetime.now(timezone.utc),
                level="error",
            )
            return

        current_phase: Optional[str] = None
        current_phase_num: Optional[int] = None

        try:
            container = self.client.containers.get(state.container_id)

            # Use asyncio queue to bridge sync Docker logs to async generator
            log_queue: asyncio.Queue[Optional[bytes]] = asyncio.Queue()

            # Capture the event loop before starting the thread
            loop = asyncio.get_running_loop()

            def read_logs():
                """Synchronous function to read logs and put them in the queue"""
                try:
                    for line in container.logs(stream=True, follow=True, timestamps=True):
                        asyncio.run_coroutine_threadsafe(
                            log_queue.put(line),
                            loop
                        ).result(timeout=5)
                        # Check if container is still running
                        try:
                            container.reload()
                            if container.status != "running":
                                break
                        except Exception:
                            break
                except Exception as e:
                    logger.error(f"Error in log reader thread: {e}")
                finally:
                    # Signal end of logs
                    try:
                        asyncio.run_coroutine_threadsafe(
                            log_queue.put(None),
                            loop
                        ).result(timeout=5)
                    except Exception:
                        pass

            # Start log reader in a thread
            loop.run_in_executor(None, read_logs)

            # Process logs from queue
            while True:
                try:
                    line = await asyncio.wait_for(log_queue.get(), timeout=1.0)
                    if line is None:
                        break

                    decoded_line = line.decode("utf-8", errors="replace").strip()
                    if decoded_line:
                        # Parse Docker timestamp prefix (RFC3339Nano format)
                        docker_ts = None
                        log_text = decoded_line
                        # Docker timestamps look like: 2024-01-15T10:30:00.123456789Z <log line>
                        if len(decoded_line) > 30 and decoded_line[4] == '-' and decoded_line[10] == 'T':
                            space_idx = decoded_line.find(' ')
                            if space_idx > 0:
                                ts_str = decoded_line[:space_idx]
                                try:
                                    # Truncate nanoseconds to microseconds for stdlib compatibility
                                    # Docker: 2024-01-15T10:30:00.123456789Z -> 2024-01-15T10:30:00.123456+00:00
                                    ts_clean = ts_str.replace('Z', '+00:00')
                                    dot_idx = ts_clean.find('.')
                                    plus_idx = ts_clean.find('+', dot_idx) if dot_idx > 0 else -1
                                    if dot_idx > 0 and plus_idx > 0:
                                        frac = ts_clean[dot_idx + 1:plus_idx][:6]  # max 6 digits
                                        ts_clean = ts_clean[:dot_idx + 1] + frac + ts_clean[plus_idx:]
                                    docker_ts = datetime.fromisoformat(ts_clean)
                                    log_text = decoded_line[space_idx + 1:]
                                except (ValueError, OverflowError):
                                    pass

                        event = self._parse_log_line(log_text, current_phase, current_phase_num, timestamp=docker_ts)

                        # Update current phase tracking
                        if event.is_phase_start:
                            current_phase = event.phase
                            current_phase_num = event.phase_number

                            # Update state
                            if project_id in self.running_states:
                                self.running_states[project_id].current_phase = current_phase
                                self.running_states[project_id].phase_number = current_phase_num

                        yield event

                except asyncio.TimeoutError:
                    # Check if container is still running
                    try:
                        container.reload()
                        if container.status != "running":
                            break
                    except Exception:
                        break

        except NotFound:
            yield ReconLogEvent(
                log="Container stopped",
                timestamp=datetime.now(timezone.utc),
                level="info",
            )
        except Exception as e:
            yield ReconLogEvent(
                log=f"Error streaming logs: {e}",
                timestamp=datetime.now(timezone.utc),
                level="error",
            )

    def get_running_count(self) -> int:
        """Get count of running recon processes"""
        return sum(1 for s in self.running_states.values() if s.status == ReconStatus.RUNNING)

    async def cleanup(self):
        """Cleanup all running containers on shutdown"""
        for project_id in list(self.running_states.keys()):
            try:
                await self.stop_recon(project_id, timeout=5)
            except Exception as e:
                logger.error(f"Error cleaning up {project_id}: {e}")
