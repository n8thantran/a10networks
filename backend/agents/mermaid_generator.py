"""
Generate Mermaid diagrams from network data
"""
from typing import Dict, Any, List, Optional
import hashlib

class MermaidGenerator:
    """Generate Mermaid diagram syntax from network data"""
    
    def __init__(self):
        self.node_shapes = {
            "server": "[(Server)]",
            "router": "{{Router}}",
            "firewall": "[/Firewall/]",
            "switch": "[[Switch]]",
            "host": "([Host])",
            "unknown": "[Unknown]"
        }
    
    def generate_network_graph(self, nodes: List[Dict], connections: List[Dict], 
                              title: str = "Network Topology") -> str:
        """Generate a complete network graph"""
        mermaid = ["graph TB"]
        
        if title:
            mermaid.append(f"    %% {title}")
        
        # Add nodes
        node_map = {}
        for node in nodes:
            node_id = node.get("id", hashlib.md5(node["ip"].encode()).hexdigest()[:8])
            node_map[node_id] = node
            
            node_type = node.get("type", "host")
            shape = self.node_shapes.get(node_type, "[Host]")
            
            # Format node label - escape quotes and special characters
            ip = node['ip'].replace('"', '')
            hostname = node.get("hostname")
            if hostname:
                hostname = hostname.replace('"', '')
            else:
                hostname = ""
            
            if hostname:
                label = f"{hostname}<br/>{ip}"
            else:
                label = ip
            
            # Add styling based on risk or status
            style_class = self._get_node_style_class(node)
            
            # Build node definition based on type - simplified for better compatibility
            if node_type == "server":
                mermaid.append(f'    {node_id}["{label}"]:::server')
            elif node_type == "router":
                mermaid.append(f'    {node_id}["{label}"]:::router')
            elif node_type == "firewall":
                mermaid.append(f'    {node_id}["{label}"]:::firewall')
            elif node_type == "switch":
                mermaid.append(f'    {node_id}["{label}"]:::switch')
            elif node_type == "host":
                mermaid.append(f'    {node_id}["{label}"]:::host')
            else:
                mermaid.append(f'    {node_id}["{label}"]')
            if style_class:
                mermaid.append(f"    class {node_id} {style_class}")
        
        # Add connections
        for conn in connections:
            source = conn["source"]
            target = conn["target"]
            
            # Connection label
            label = f"{conn['protocol'].upper()}:{conn['port']}"
            
            # Connection style based on threat level
            if conn.get("threat_level") == "high":
                mermaid.append(f"    {source} -.->|{label}| {target}")
            elif conn.get("threat_level") == "medium":
                mermaid.append(f"    {source} -->|{label}| {target}")
            else:
                mermaid.append(f"    {source} -->|{label}| {target}")
        
        # Add styling definitions
        mermaid.extend(self._get_style_definitions())
        
        return "\n".join(mermaid)
    
    def generate_flow_diagram(self, flow_data: Dict) -> str:
        """Generate a flow diagram for packet flow or data flow"""
        mermaid = ["flowchart LR"]
        
        # Parse flow stages
        if "stages" in flow_data:
            for i, stage in enumerate(flow_data["stages"]):
                stage_id = f"S{i}"
                mermaid.append(f"    {stage_id}[{stage['name']}]")
                
                if i > 0:
                    prev_id = f"S{i-1}"
                    mermaid.append(f"    {prev_id} --> {stage_id}")
        
        return "\n".join(mermaid)
    
    def generate_sequence_diagram(self, interactions: List[Dict]) -> str:
        """Generate sequence diagram for network interactions"""
        mermaid = ["sequenceDiagram"]
        
        # Add participants
        participants = set()
        for interaction in interactions:
            participants.add(interaction.get("source"))
            participants.add(interaction.get("target"))
        
        for p in participants:
            if p:
                mermaid.append(f"    participant {self._sanitize_id(p)}")
        
        # Add interactions
        for interaction in interactions:
            source = self._sanitize_id(interaction.get("source"))
            target = self._sanitize_id(interaction.get("target"))
            message = interaction.get("message", "data")
            
            if interaction.get("type") == "request":
                mermaid.append(f"    {source}->>+{target}: {message}")
            elif interaction.get("type") == "response":
                mermaid.append(f"    {target}-->>-{source}: {message}")
            else:
                mermaid.append(f"    {source}->>{target}: {message}")
        
        return "\n".join(mermaid)
    
    def generate_pie_chart(self, data: Dict[str, int], title: str = "Distribution") -> str:
        """Generate pie chart for distributions"""
        mermaid = [f"pie title {title}"]
        
        for label, value in data.items():
            mermaid.append(f'    "{label}" : {value}')
        
        return "\n".join(mermaid)
    
    def generate_gantt_chart(self, timeline_data: List[Dict]) -> str:
        """Generate Gantt chart for timeline visualization"""
        mermaid = ["gantt", "    title Network Events Timeline", "    dateFormat YYYY-MM-DD HH:mm:ss"]
        
        sections = {}
        for event in timeline_data:
            section = event.get("category", "Events")
            if section not in sections:
                sections[section] = []
                mermaid.append(f"    section {section}")
            
            task_name = event.get("name", "Event")
            start_time = event.get("start")
            duration = event.get("duration", "1h")
            
            mermaid.append(f"    {task_name} : {start_time}, {duration}")
        
        return "\n".join(mermaid)
    
    def generate_state_diagram(self, states: List[Dict], transitions: List[Dict]) -> str:
        """Generate state diagram for connection states or system states"""
        mermaid = ["stateDiagram-v2"]
        
        # Add states
        for state in states:
            state_id = self._sanitize_id(state["id"])
            state_name = state.get("name", state_id)
            
            if state.get("type") == "start":
                mermaid.append(f"    [*] --> {state_id}")
            elif state.get("type") == "end":
                mermaid.append(f"    {state_id} --> [*]")
            
            mermaid.append(f"    {state_id} : {state_name}")
        
        # Add transitions
        for trans in transitions:
            from_state = self._sanitize_id(trans["from"])
            to_state = self._sanitize_id(trans["to"])
            label = trans.get("label", "")
            
            if label:
                mermaid.append(f"    {from_state} --> {to_state} : {label}")
            else:
                mermaid.append(f"    {from_state} --> {to_state}")
        
        return "\n".join(mermaid)
    
    def generate_mindmap(self, root: str, branches: Dict) -> str:
        """Generate mindmap for network hierarchy"""
        mermaid = ["mindmap", f"  root(({root}))"]
        
        def add_branches(parent_indent: int, items: Dict):
            for key, value in items.items():
                indent = "  " * (parent_indent + 1)
                mermaid.append(f"{indent}{key}")
                
                if isinstance(value, dict):
                    add_branches(parent_indent + 1, value)
                elif isinstance(value, list):
                    for item in value:
                        item_indent = "  " * (parent_indent + 2)
                        mermaid.append(f"{item_indent}{item}")
        
        add_branches(1, branches)
        
        return "\n".join(mermaid)
    
    def generate_threat_graph(self, threats: List[Dict], nodes: List[Dict]) -> str:
        """Generate a threat visualization graph"""
        mermaid = ["graph TB"]
        mermaid.append("    %% Threat Visualization")
        
        # Group threats by source
        threat_sources = {}
        for threat in threats:
            source = threat.get("source", "unknown")
            if source not in threat_sources:
                threat_sources[source] = []
            threat_sources[source].append(threat)
        
        # Add threat source nodes
        for source, source_threats in threat_sources.items():
            source_id = self._sanitize_id(f"threat_{source}")
            severity = max(t.get("severity", "low") for t in source_threats)
            
            mermaid.append(f"    {source_id}[Threat: {source}]")
            mermaid.append(f"    class {source_id} threat-{severity}")
            
            # Add connections to targets
            for threat in source_threats:
                if threat.get("target"):
                    target_id = self._sanitize_id(threat["target"])
                    threat_type = threat.get("type", "unknown")
                    mermaid.append(f"    {source_id} -.->|{threat_type}| {target_id}[{threat['target']}]")
        
        # Add styling
        mermaid.append("    classDef threat-high fill:#f96,stroke:#c30,stroke-width:2px")
        mermaid.append("    classDef threat-medium fill:#fc6,stroke:#f90,stroke-width:2px")
        mermaid.append("    classDef threat-low fill:#ff9,stroke:#fc0,stroke-width:1px")
        
        return "\n".join(mermaid)
    
    def generate_from_query_result(self, query_result: Dict) -> Optional[str]:
        """Generate appropriate diagram based on query result"""
        if not query_result.get("success"):
            return None
        
        data = query_result.get("data", {})
        viz_type = query_result.get("visualization", "table")
        
        # Generate based on visualization type
        if viz_type == "network_graph":
            nodes = data.get("nodes", []) or data.get("summary", {}).get("nodes", [])
            connections = data.get("connections", []) or data.get("summary", {}).get("connections", [])
            return self.generate_network_graph(nodes, connections)
        
        elif viz_type == "directed_graph":
            if "connections" in data:
                # Extract unique nodes from connections
                nodes = []
                node_ips = set()
                
                for conn_type in ["incoming", "outgoing"]:
                    if conn_type in data["connections"]:
                        for conn in data["connections"][conn_type]:
                            # Add source and target as nodes if not present
                            src_id = conn.get("source")
                            tgt_id = conn.get("target")
                            
                            # This is simplified - in production you'd look up actual node data
                            if src_id and src_id not in node_ips:
                                nodes.append({"id": src_id, "ip": src_id})
                                node_ips.add(src_id)
                            if tgt_id and tgt_id not in node_ips:
                                nodes.append({"id": tgt_id, "ip": tgt_id})
                                node_ips.add(tgt_id)
                
                all_connections = data["connections"].get("incoming", []) + data["connections"].get("outgoing", [])
                return self.generate_network_graph(nodes, all_connections, f"Connections for {data.get('host', 'Host')}")
        
        elif viz_type == "star_graph":
            # Create star topology with target in center
            target = data.get("target", "Target")
            talkers = data.get("talkers", [])
            
            nodes = [{"id": "center", "ip": target, "type": "server"}]
            connections = []
            
            for i, talker in enumerate(talkers):
                talker_id = f"talker_{i}"
                nodes.append({"id": talker_id, "ip": talker})
                connections.append({
                    "source": talker_id,
                    "target": "center",
                    "protocol": "tcp",
                    "port": "*"
                })
            
            return self.generate_network_graph(nodes, connections, f"Nodes talking to {target}")
        
        elif viz_type == "pie_chart":
            if "protocols" in data:
                proto_data = {
                    proto: info["count"] 
                    for proto, info in data["protocols"].items()
                }
                return self.generate_pie_chart(proto_data, "Protocol Distribution")
        
        elif viz_type == "timeline":
            if "anomalies" in data:
                timeline_data = [
                    {
                        "name": a.get("type", "Anomaly"),
                        "start": a.get("timestamp"),
                        "category": a.get("severity", "medium").title()
                    }
                    for a in data["anomalies"]
                ]
                return self.generate_gantt_chart(timeline_data)
        
        return None
    
    def _sanitize_id(self, text: str) -> str:
        """Sanitize text to be used as Mermaid ID"""
        if not text:
            return "unknown"
        
        # Replace problematic characters
        sanitized = text.replace(".", "_")
        sanitized = sanitized.replace(":", "_")
        sanitized = sanitized.replace("-", "_")
        sanitized = sanitized.replace(" ", "_")
        
        # Ensure it starts with a letter
        if sanitized and sanitized[0].isdigit():
            sanitized = f"n_{sanitized}"
        
        return sanitized
    
    def _get_node_style_class(self, node: Dict) -> str:
        """Get style class for a node based on its properties"""
        risk_score = node.get("risk_score", 0)
        
        if risk_score > 75:
            return "high-risk"
        elif risk_score > 50:
            return "medium-risk"
        elif risk_score > 25:
            return "low-risk"
        
        return "normal"
    
    def _get_style_definitions(self) -> List[str]:
        """Get Mermaid style definitions"""
        return [
            "    classDef server fill:#4ade80,stroke:#22c55e,stroke-width:2px,color:#fff",
            "    classDef router fill:#60a5fa,stroke:#3b82f6,stroke-width:2px,color:#fff",
            "    classDef firewall fill:#f87171,stroke:#ef4444,stroke-width:2px,color:#fff",
            "    classDef switch fill:#a78bfa,stroke:#8b5cf6,stroke-width:2px,color:#fff",
            "    classDef host fill:#fbbf24,stroke:#f59e0b,stroke-width:2px,color:#000",
            "    classDef high-risk fill:#f96,stroke:#c30,stroke-width:3px",
            "    classDef medium-risk fill:#fc6,stroke:#f90,stroke-width:2px",
            "    classDef low-risk fill:#ff9,stroke:#fc0,stroke-width:2px",
            "    classDef normal fill:#9cf,stroke:#369,stroke-width:1px"
        ]