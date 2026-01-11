"""
RedAmon Agent Orchestrator

Main agent class that orchestrates LangGraph execution with MCP tools
and Neo4j graph database integration.
"""

import os
import logging
from typing import Optional, List

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain_core.messages import AIMessage, HumanMessage
from langgraph.graph import StateGraph, START, END
from langgraph.prebuilt import ToolNode
from langgraph.checkpoint.memory import MemorySaver

from state import AgentState, InvokeResponse
from utils import create_config, get_config_values, set_checkpointer
from params import OPENAI_MODEL, CREATE_GRAPH_IMAGRE_ON_INIT
from tools import MCPToolsManager, Neo4jToolManager, set_tenant_context

checkpointer = MemorySaver()
set_checkpointer(checkpointer)

load_dotenv()

logger = logging.getLogger(__name__)


class AgentOrchestrator:
    """
    Main orchestrator for the RedAmon agent system.

    Combines:
    - LangGraph for state management and flow control
    - MCP tools (curl) for HTTP requests
    - Neo4j text-to-cypher for graph queries
    - OpenAI GPT-4.1 for reasoning
    - MemorySaver checkpointer for session persistence
    """

    def __init__(self):
        """Initialize the orchestrator with configuration."""
        self.model_name = OPENAI_MODEL
        self.openai_api_key = os.getenv("OPENAI_API_KEY")
        self.neo4j_uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.neo4j_user = os.getenv("NEO4J_USER", "neo4j")
        self.neo4j_password = os.getenv("NEO4J_PASSWORD")

        self.llm: Optional[ChatOpenAI] = None
        self.llm_with_tools: Optional[ChatOpenAI] = None
        self.tools: List = []
        self.graph = None

        self._initialized = False

    async def initialize(self) -> None:
        """
        Initialize all components asynchronously.

        Must be called before invoke().
        """
        if self._initialized:
            logger.warning("Orchestrator already initialized")
            return
        logger.info("Initializing AgentOrchestrator...")

        self._setup_llm()
        await self._setup_tools()
        self.llm_with_tools = self.llm.bind_tools(self.tools)
        self._build_graph()
        self._initialized = True

        if CREATE_GRAPH_IMAGRE_ON_INIT:
            self._save_graph_image()

        logger.info(f"AgentOrchestrator initialized with {len(self.tools)} tools")

    def _setup_llm(self) -> None:
        """Initialize the OpenAI LLM."""
        logger.info(f"Setting up LLM: {self.model_name}")
        self.llm = ChatOpenAI(
            model=self.model_name,
            api_key=self.openai_api_key,
            temperature=0
        )

    async def _setup_tools(self) -> None:
        """Set up all tools (MCP and Neo4j)."""
        # Setup MCP tools
        mcp_manager = MCPToolsManager()
        mcp_tools = await mcp_manager.get_tools()
        self.tools.extend(mcp_tools)

        # Setup Neo4j graph query tool
        neo4j_manager = Neo4jToolManager(
            uri=self.neo4j_uri,
            user=self.neo4j_user,
            password=self.neo4j_password,
            llm=self.llm
        )
        graph_tool = neo4j_manager.get_tool()
        if graph_tool:
            self.tools.append(graph_tool)

    def _build_graph(self) -> None:
        """
        Build the LangGraph StateGraph with MemorySaver checkpointer.

        Flow: START -> agent -> tools (conditional) -> response -> END
        The response node generates a natural language answer from tool output.
        The checkpointer automatically handles session persistence.
        """
        logger.info("Building LangGraph StateGraph with MemorySaver checkpointer")

        builder = StateGraph(AgentState)
        builder.add_node("agent", self._agent_node)
        builder.add_node("tools", ToolNode(self.tools))
        builder.add_node("response", self._response_node)

        builder.add_edge(START, "agent")
        builder.add_conditional_edges(
            "agent",
            self._should_use_tool,
            {
                "tools": "tools",
                "end": END
            }
        )
        builder.add_edge("tools", "response")
        builder.add_edge("response", END)

        self.graph = builder.compile(checkpointer=checkpointer)
        logger.info("LangGraph compiled with MemorySaver checkpointer")

    def _save_graph_image(self) -> None:
        """
        Save the LangGraph structure as a PNG image.

        The image is saved to the agentic folder as 'graph_structure.png'.
        Requires pygraphviz or grandalf for rendering.
        """
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            image_path = os.path.join(current_dir, "graph_structure.png")
            png_data = self.graph.get_graph().draw_mermaid_png()

            with open(image_path, "wb") as f:
                f.write(png_data)

            logger.info(f"Graph structure image saved to {image_path}")

        except Exception as e:
            logger.warning(f"Could not save graph image: {e}")

    async def _agent_node(self, state: AgentState, config: Optional[dict] = None) -> dict:
        """
        Main reasoning node - LLM decides which tool to use.

        Args:
            state: Current agent state
            config: Contains configurable with user_id, project_id, session_id

        Returns:
            Updated state with LLM response
        """
        config = config or {}
        user_id, project_id, session_id = get_config_values(config)
        logger.info(f"[{user_id}/{project_id}/{session_id}] Agent node processing...")

        response = await self.llm_with_tools.ainvoke(state["messages"])

        logger.debug(f"[{user_id}/{project_id}/{session_id}] LLM response type: {type(response)}")

        if hasattr(response, 'tool_calls') and response.tool_calls:
            tool_name = response.tool_calls[0].get('name', 'unknown')
            logger.info(f"[{user_id}/{project_id}/{session_id}] Tool selected: {tool_name}")

        return {"messages": [response]}

    def _should_use_tool(self, state: AgentState) -> str:
        """
        Determine if we should route to tools or end.

        Args:
            state: Current agent state

        Returns:
            "tools" if tool calls present, "end" otherwise
        """
        last_message = state["messages"][-1]

        if hasattr(last_message, 'tool_calls') and last_message.tool_calls:
            return "tools"

        return "end"

    async def _response_node(self, state: AgentState, config: Optional[dict] = None) -> dict:
        """
        Response node - generates a natural language answer from tool output.

        This node takes the tool output and asks the LLM to create a
        human-friendly response summarizing the results.

        Args:
            state: Current agent state (contains tool output in messages)
            config: Contains configurable with user_id, project_id, session_id

        Returns:
            Updated state with natural language response
        """
        config = config or {}
        user_id, project_id, session_id = get_config_values(config)
        logger.info(f"[{user_id}/{project_id}/{session_id}] Response node processing...")

        response = await self.llm.ainvoke(state["messages"])

        logger.debug(f"[{user_id}/{project_id}/{session_id}] Generated response")

        return {"messages": [response]}

    async def invoke(
        self,
        question: str,
        user_id: str,
        project_id: str,
        session_id: str
    ) -> InvokeResponse:
        """Main entry point for agent invocation."""
        if not self._initialized:
            raise RuntimeError("Orchestrator not initialized. Call initialize() first.")

        logger.info(f"[{user_id}/{project_id}/{session_id}] Invoking with: {question[:50]}...")

        # Set context variables for tenant filtering in graph queries
        set_tenant_context(user_id, project_id)

        try:
            config = create_config(user_id, project_id, session_id)
            input_data = {
                "messages": [HumanMessage(content=question)]
            }

            final_state = await self.graph.ainvoke(input_data, config)

            tool_used = None
            tool_output = None

            for msg in final_state.get("messages", []):
                if hasattr(msg, 'tool_calls') and msg.tool_calls:
                    tool_used = msg.tool_calls[0].get('name')
                if hasattr(msg, 'name') and hasattr(msg, 'content'):
                    tool_output = msg.content

            final_answer = ""
            for msg in reversed(final_state.get("messages", [])):
                if isinstance(msg, AIMessage) and not hasattr(msg, 'name'):
                    final_answer = msg.content
                    break

            if not final_answer and tool_output:
                final_answer = tool_output

            logger.info(f"[{user_id}/{project_id}/{session_id}] Completed. Tool: {tool_used}")

            return InvokeResponse(
                answer=final_answer,
                tool_used=tool_used,
                tool_output=tool_output
            )

        except Exception as e:
            logger.error(f"[{user_id}/{project_id}/{session_id}] Error: {e}")
            return InvokeResponse(error=str(e))

    async def close(self) -> None:
        """Clean up resources."""
        self._initialized = False
        logger.info("AgentOrchestrator closed - placeolder")
