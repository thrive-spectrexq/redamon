"""
RedAmon Agent Tools

MCP tools and Neo4j graph query tool definitions.
"""

import re
import logging
from typing import List, Optional, TYPE_CHECKING
from contextvars import ContextVar

from langchain_core.tools import tool
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_neo4j import Neo4jGraph

from params import MCP_CURL_URL, CYPHER_MAX_RETRIES
from prompts import TEXT_TO_CYPHER_SYSTEM

if TYPE_CHECKING:
    from langchain_openai import ChatOpenAI

logger = logging.getLogger(__name__)

# Context variables to pass user_id and project_id to tools
current_user_id: ContextVar[str] = ContextVar('current_user_id', default='')
current_project_id: ContextVar[str] = ContextVar('current_project_id', default='')


def set_tenant_context(user_id: str, project_id: str) -> None:
    """Set the current user and project context for tool execution."""
    current_user_id.set(user_id)
    current_project_id.set(project_id)


class MCPToolsManager:
    """Manages MCP (Model Context Protocol) tool connections."""

    def __init__(self, curl_url: str = MCP_CURL_URL):
        self.curl_url = curl_url
        self.client: Optional[MultiServerMCPClient] = None

    async def get_tools(self) -> List:
        """
        Connect to MCP servers and load tools.

        Returns:
            List of MCP tools available for use
        """
        logger.info(f"Connecting to MCP curl server at {self.curl_url}")

        try:
            self.client = MultiServerMCPClient({
                "curl": {
                    "url": self.curl_url,
                    "transport": "sse",
                }
            })

            mcp_tools = await self.client.get_tools()
            logger.info(f"Loaded {len(mcp_tools)} tools from MCP server")
            return mcp_tools

        except Exception as e:
            logger.error(f"Failed to connect to MCP server: {e}")
            logger.warning("Continuing without MCP tools")
            return []


class Neo4jToolManager:
    """Manages Neo4j graph query tool with tenant filtering."""

    # Node types that require tenant filtering (exclude CVE which is global)
    TENANT_NODES = {
        'Domain', 'Subdomain', 'IP', 'Port', 'Service', 'BaseURL',
        'Technology', 'Vulnerability', 'Endpoint', 'Parameter',
        'Header', 'DNSRecord', 'Certificate', 'MitreData', 'Capec'
    }

    def __init__(self, uri: str, user: str, password: str, llm: "ChatOpenAI"):
        self.uri = uri
        self.user = user
        self.password = password
        self.llm = llm
        self.graph: Optional[Neo4jGraph] = None

    def _inject_tenant_filter(self, cypher: str, user_id: str, project_id: str) -> str:
        """
        Inject mandatory user_id and project_id filters into a Cypher query.

        This ensures all queries are scoped to the current user's project,
        preventing cross-tenant data access.

        Args:
            cypher: The AI-generated Cypher query
            user_id: Current user's ID
            project_id: Current project's ID

        Returns:
            Modified Cypher query with tenant filters applied
        """
        # Find all node variable declarations in MATCH clauses
        # Pattern matches: (variable:Label) or (variable:Label {props})
        node_pattern = r'\((\w+):(\w+)(?:\s*\{[^}]*\})?\)'

        # Find all node variables that need filtering
        matches = re.findall(node_pattern, cypher)
        filter_vars = []
        for var_name, label in matches:
            if label in self.TENANT_NODES:
                filter_vars.append(var_name)

        if not filter_vars:
            return cypher

        # Build the tenant filter clause
        tenant_conditions = []
        for var in set(filter_vars):  # Use set to avoid duplicates
            tenant_conditions.append(f"{var}.user_id = $tenant_user_id")
            tenant_conditions.append(f"{var}.project_id = $tenant_project_id")

        tenant_filter = " AND ".join(tenant_conditions)

        # Inject the filter into the query
        # If WHERE exists, add to it; otherwise insert WHERE before RETURN/WITH/ORDER/LIMIT
        if re.search(r'\bWHERE\b', cypher, re.IGNORECASE):
            # Add to existing WHERE clause
            cypher = re.sub(
                r'(\bWHERE\b\s+)',
                rf'\1({tenant_filter}) AND ',
                cypher,
                count=1,
                flags=re.IGNORECASE
            )
        else:
            # Insert WHERE before RETURN, WITH, ORDER BY, or LIMIT
            insert_pattern = r'(\s*)(RETURN|WITH|ORDER\s+BY|LIMIT)'
            match = re.search(insert_pattern, cypher, re.IGNORECASE)
            if match:
                insert_pos = match.start()
                cypher = cypher[:insert_pos] + f" WHERE {tenant_filter} " + cypher[insert_pos:]

        return cypher

    async def _generate_cypher(
        self,
        question: str,
        previous_error: str = None,
        previous_cypher: str = None
    ) -> str:
        """
        Use LLM to generate a Cypher query from natural language.

        Args:
            question: Natural language question about the data
            previous_error: Optional error message from a previous failed attempt
            previous_cypher: Optional previous Cypher query that failed

        Returns:
            Generated Cypher query string
        """
        schema = self.graph.get_schema

        # Build the prompt with optional error context for retries
        error_context = ""
        if previous_error and previous_cypher:
            error_context = f"""

## Previous Attempt Failed
The previous query failed with an error. Please fix the issue.

Failed Query:
{previous_cypher}

Error Message:
{previous_error}

Common fixes:
- Check relationship direction syntax: use <-[:REL]- not [:REL]<-
- Ensure node labels and property names match the schema
- Verify relationship types exist in the schema
"""

        prompt = f"""{TEXT_TO_CYPHER_SYSTEM}

## Current Database Schema
{schema}
{error_context}
## Important
- Generate ONLY the Cypher query, no explanations
- Do NOT include user_id or project_id filters - they will be added automatically
- Always use LIMIT to restrict results

User Question: {question}

Cypher Query:"""

        response = await self.llm.ainvoke(prompt)
        cypher = response.content.strip()

        # Clean up the response - remove markdown code blocks if present
        if cypher.startswith("```"):
            lines = cypher.split("\n")
            cypher = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])

        return cypher.strip()

    def get_tool(self) -> Optional[callable]:
        """
        Set up and return the Neo4j text-to-cypher tool.

        Returns:
            The query_graph tool function, or None if setup fails
        """
        logger.info(f"Setting up Neo4j connection to {self.uri}")

        try:
            self.graph = Neo4jGraph(
                url=self.uri,
                username=self.user,
                password=self.password
            )

            # Store reference to self for use in the tool closure
            manager = self

            @tool
            async def query_graph(question: str) -> str:
                """
                Query the Neo4j graph database using natural language.

                Use this tool to retrieve reconnaissance data such as:
                - Domains, subdomains, and their relationships
                - IP addresses and their associated ports/services
                - Technologies detected on targets
                - Vulnerabilities and CVEs found
                - Any other security reconnaissance data

                Args:
                    question: Natural language question about the data

                Returns:
                    Query results as a string
                """
                # Get current user/project from context
                user_id = current_user_id.get()
                project_id = current_project_id.get()

                if not user_id or not project_id:
                    return "Error: Missing user_id or project_id context"

                logger.info(f"[{user_id}/{project_id}] Generating Cypher for: {question[:50]}...")

                last_error = None
                last_cypher = None

                for attempt in range(CYPHER_MAX_RETRIES):
                    try:
                        # Step 1: Generate Cypher from natural language (with error context on retry)
                        if attempt == 0:
                            cypher = await manager._generate_cypher(question)
                        else:
                            logger.info(f"[{user_id}/{project_id}] Retry {attempt}/{CYPHER_MAX_RETRIES - 1}: Regenerating Cypher...")
                            cypher = await manager._generate_cypher(
                                question,
                                previous_error=last_error,
                                previous_cypher=last_cypher
                            )

                        logger.info(f"[{user_id}/{project_id}] Generated Cypher (attempt {attempt + 1}): {cypher}")

                        # Step 2: Inject mandatory tenant filters
                        filtered_cypher = manager._inject_tenant_filter(cypher, user_id, project_id)
                        logger.info(f"[{user_id}/{project_id}] Filtered Cypher: {filtered_cypher}")

                        # Step 3: Execute the filtered query
                        result = manager.graph.query(
                            filtered_cypher,
                            params={
                                "tenant_user_id": user_id,
                                "tenant_project_id": project_id
                            }
                        )

                        if not result:
                            return "No results found"

                        return str(result)

                    except Exception as e:
                        error_msg = str(e)
                        logger.warning(f"[{user_id}/{project_id}] Query attempt {attempt + 1} failed: {error_msg}")
                        last_error = error_msg
                        last_cypher = cypher if 'cypher' in locals() else None

                        # If this is the last attempt, return the error
                        if attempt == CYPHER_MAX_RETRIES - 1:
                            logger.error(f"[{user_id}/{project_id}] All {CYPHER_MAX_RETRIES} attempts failed")
                            return f"Error querying graph after {CYPHER_MAX_RETRIES} attempts: {error_msg}"

                return "Error: Unexpected end of retry loop"

            logger.info("Neo4j graph query tool configured with tenant filtering")
            return query_graph

        except Exception as e:
            logger.error(f"Failed to set up Neo4j: {e}")
            logger.warning("Continuing without graph query tool")
            return None
