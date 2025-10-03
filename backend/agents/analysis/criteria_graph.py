"""
Multi-agent workflow for criteria selection and validation
Uses cyclic graph pattern to prevent hallucinations
"""
import asyncio
import json
import logging
from typing import Dict, Any, List, TypedDict
from enum import Enum
from langgraph.graph import StateGraph, END
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage
from langchain_openai import ChatOpenAI
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NodeState(str, Enum):
    CRITERIA_SELECTOR = "criteria_selector"
    QA_VALIDATOR = "qa_validator"
    FILTER_GENERATOR = "filter_generator"
    END = "end"

class GraphState(TypedDict):
    """State passed between nodes in the graph"""
    user_description: str
    selected_criteria: List[Dict[str, Any]]
    validation_result: Dict[str, Any]
    scapy_filter: str
    iteration_count: int
    max_iterations: int
    errors: List[str]
    final_output: Dict[str, Any]

class CriteriaSelectionWorkflow:
    """Manages the criteria selection and validation workflow"""
    
    def __init__(self):
        # Initialize OpenAI GPT-4o-mini
        self.llm = ChatOpenAI(
            model="gpt-4o-mini",
            api_key=os.getenv("OPENAI_API_KEY"),
            temperature=0.2,
            max_tokens=2000
        )
        
        # Build the workflow graph
        self.workflow = self._build_graph()
        
        # Criteria knowledge base (simulating vector store)
        self.criteria_db = self._initialize_criteria_db()
    
    def _initialize_criteria_db(self) -> List[Dict[str, Any]]:
        """Initialize the criteria knowledge base"""
        return [
            {
                "id": "http_traffic",
                "description": "HTTP/HTTPS web traffic",
                "filter": "tcp port 80 or tcp port 443",
                "tags": ["web", "http", "https", "browser"]
            },
            {
                "id": "dns_traffic", 
                "description": "DNS queries and responses",
                "filter": "udp port 53",
                "tags": ["dns", "domain", "resolution"]
            },
            {
                "id": "ssh_traffic",
                "description": "SSH connections",
                "filter": "tcp port 22",
                "tags": ["ssh", "secure shell", "remote"]
            },
            {
                "id": "sql_traffic",
                "description": "Database traffic (MySQL, PostgreSQL)",
                "filter": "tcp port 3306 or tcp port 5432",
                "tags": ["database", "mysql", "postgresql", "sql"]
            },
            {
                "id": "suspicious_ports",
                "description": "Traffic on commonly exploited ports",
                "filter": "tcp port 445 or tcp port 139 or tcp port 135",
                "tags": ["suspicious", "smb", "netbios", "rpc"]
            },
            {
                "id": "icmp_traffic",
                "description": "ICMP packets (ping, traceroute)",
                "filter": "icmp",
                "tags": ["icmp", "ping", "traceroute"]
            },
            {
                "id": "large_packets",
                "description": "Unusually large packets",
                "filter": "greater 1500",
                "tags": ["large", "jumbo", "fragmented"]
            },
            {
                "id": "syn_flood",
                "description": "Potential SYN flood attack patterns",
                "filter": "tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0",
                "tags": ["attack", "syn", "flood", "dos"]
            }
        ]
    
    def _build_graph(self) -> StateGraph:
        """Build the LangGraph workflow"""
        workflow = StateGraph(GraphState)
        
        # Add nodes
        workflow.add_node(NodeState.CRITERIA_SELECTOR, self.criteria_selector_node)
        workflow.add_node(NodeState.QA_VALIDATOR, self.qa_validator_node)
        workflow.add_node(NodeState.FILTER_GENERATOR, self.filter_generator_node)
        
        # Add edges with conditional logic
        workflow.set_entry_point(NodeState.CRITERIA_SELECTOR)
        
        # Conditional edges based on validation
        workflow.add_conditional_edges(
            NodeState.CRITERIA_SELECTOR,
            lambda x: NodeState.QA_VALIDATOR if x["selected_criteria"] else NodeState.FILTER_GENERATOR
        )
        
        workflow.add_conditional_edges(
            NodeState.QA_VALIDATOR,
            self.validation_router
        )
        
        workflow.add_edge(NodeState.FILTER_GENERATOR, END)
        
        return workflow.compile()
    
    async def criteria_selector_node(self, state: GraphState) -> GraphState:
        """Select relevant criteria based on user description"""
        logger.info("Criteria Selector: Processing user description")
        
        user_desc = state["user_description"]
        
        # Use LLM to understand intent
        prompt = f"""
        Given this network traffic description: "{user_desc}"
        
        Identify what type of network traffic the user wants to capture.
        Consider: protocols, ports, packet characteristics, security concerns.
        
        Available criteria types:
        - HTTP/HTTPS traffic
        - DNS queries
        - SSH connections
        - Database traffic
        - Suspicious ports
        - ICMP packets
        - Large packets
        - Attack patterns
        
        Respond with the most relevant traffic types in order of relevance.
        """
        
        try:
            response = await self.llm.ainvoke([
                SystemMessage(content="You are a network security expert."),
                HumanMessage(content=prompt)
            ])
            
            # Match against criteria database
            selected = []
            response_text = response.content.lower()
            
            for criteria in self.criteria_db:
                for tag in criteria["tags"]:
                    if tag in response_text:
                        selected.append(criteria)
                        break
            
            # Limit to top 3 most relevant
            state["selected_criteria"] = selected[:3]
            
        except Exception as e:
            logger.error(f"Criteria selection error: {e}")
            state["errors"].append(str(e))
            state["selected_criteria"] = []
        
        return state
    
    async def qa_validator_node(self, state: GraphState) -> GraphState:
        """Validate selected criteria against user intent"""
        logger.info("QA Validator: Validating criteria selection")
        
        user_desc = state["user_description"]
        selected = state["selected_criteria"]
        
        if not selected:
            state["validation_result"] = {"valid": False, "reason": "No criteria selected"}
            return state
        
        # Build validation prompt
        criteria_summary = "\n".join([
            f"- {c['description']}: {c['filter']}" 
            for c in selected
        ])
        
        prompt = f"""
        User requested: "{user_desc}"
        
        Selected filters:
        {criteria_summary}
        
        Validate if these filters correctly match the user's intent.
        Consider:
        1. Do the filters capture the requested traffic type?
        2. Are there any missing traffic types?
        3. Are there any incorrect filters included?
        
        Respond with:
        - VALID if the selection is correct
        - INVALID if it needs adjustment
        - Explanation of any issues
        """
        
        try:
            response = await self.llm.ainvoke([
                SystemMessage(content="You are a network security QA expert."),
                HumanMessage(content=prompt)
            ])
            
            response_text = response.content.upper()
            is_valid = "VALID" in response_text and "INVALID" not in response_text
            
            state["validation_result"] = {
                "valid": is_valid,
                "explanation": response.content
            }
            
        except Exception as e:
            logger.error(f"Validation error: {e}")
            state["validation_result"] = {"valid": False, "reason": str(e)}
        
        state["iteration_count"] += 1
        return state
    
    async def filter_generator_node(self, state: GraphState) -> GraphState:
        """Generate final Scapy filter string"""
        logger.info("Filter Generator: Creating Scapy filter")
        
        selected = state["selected_criteria"]
        
        if not selected:
            # Generate custom filter from description
            user_desc = state["user_description"]
            
            prompt = f"""
            Create a BPF (Berkeley Packet Filter) expression for Scapy to capture:
            "{user_desc}"
            
            Examples of valid BPF filters:
            - tcp port 80
            - udp and port 53
            - host 192.168.1.1
            - net 192.168.0.0/24
            - tcp[tcpflags] & (tcp-syn) != 0
            
            Provide ONLY the filter expression, no explanation.
            """
            
            try:
                response = await self.llm.ainvoke([
                    SystemMessage(content="You are a BPF filter expert."),
                    HumanMessage(content=prompt)
                ])
                
                filter_string = response.content.strip()
                # Clean up the filter
                filter_string = filter_string.replace('"', '').replace("'", '')
                
            except Exception as e:
                logger.error(f"Filter generation error: {e}")
                filter_string = ""
        else:
            # Combine selected filters
            filters = [c["filter"] for c in selected]
            filter_string = " or ".join(f"({f})" for f in filters)
        
        state["scapy_filter"] = filter_string
        state["final_output"] = {
            "scapy_filter": filter_string,
            "selected_criteria": selected,
            "validation_result": state.get("validation_result", {})
        }
        
        return state
    
    def validation_router(self, state: GraphState) -> str:
        """Route based on validation result"""
        validation = state.get("validation_result", {})
        iteration = state.get("iteration_count", 0)
        max_iter = state.get("max_iterations", 3)
        
        if validation.get("valid", False) or iteration >= max_iter:
            return NodeState.FILTER_GENERATOR
        else:
            # Loop back for another iteration
            return NodeState.CRITERIA_SELECTOR
    
    async def process_description(
        self, 
        description: str,
        user_id: str = "default"
    ) -> Dict[str, Any]:
        """Process user description through the workflow"""
        
        initial_state = GraphState(
            user_description=description,
            selected_criteria=[],
            validation_result={},
            scapy_filter="",
            iteration_count=0,
            max_iterations=3,
            errors=[],
            final_output={}
        )
        
        try:
            # Run the workflow
            result = await self.workflow.ainvoke(initial_state)
            
            return result["final_output"]
            
        except Exception as e:
            logger.error(f"Workflow execution error: {e}")
            return {
                "error": str(e),
                "scapy_filter": "",
                "validation_result": {"valid": False, "reason": str(e)}
            }


if __name__ == "__main__":
    # Test the workflow
    async def test_workflow():
        workflow = CriteriaSelectionWorkflow()
        
        test_cases = [
            "I want to monitor all web traffic",
            "Show me suspicious SQL injection attempts",
            "Capture DNS queries from internal network",
            "Monitor for potential DDoS attacks"
        ]
        
        for description in test_cases:
            print(f"\nTesting: {description}")
            result = await workflow.process_description(description)
            print(f"Filter: {result.get('scapy_filter', 'None')}")
            print(f"Validation: {result.get('validation_result', {})}")
    
    asyncio.run(test_workflow())