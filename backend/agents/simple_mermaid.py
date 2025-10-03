"""
Simplified Mermaid diagram generator with guaranteed compatibility
"""
from typing import Dict, Any, List

class SimpleMermaidGenerator:
    """Generate simple, compatible Mermaid diagrams"""
    
    def generate_attack_flow(self, attack_type: str, stats: Dict[str, Any]) -> str:
        """Generate simple attack flow diagram"""
        total_requests = stats.get("total_requests", 0)
        blocked = stats.get("blocked_requests", 0)
        
        # Use simplest possible syntax
        diagram = f"""graph LR
    A[Attackers] --> B[DDoS Attack]
    B --> C[{attack_type}]
    C --> D[Target Server]
    C --> E[{total_requests} Requests]
    E --> F[{blocked} Blocked]"""
        
        return diagram
    
    def generate_mitigation_flow(self, protection_data: Dict[str, Any]) -> str:
        """Generate simple mitigation diagram"""
        blocked_ips = protection_data.get("blocked_count", 0)
        current_rps = protection_data.get("current_rps", 0)
        
        # Build diagram without f-string to avoid curly brace issues
        diagram = "graph TD\n"
        diagram += "    A[Incoming Traffic] --> B[Detection]\n"
        diagram += "    B --> C[Check Attack]\n"
        diagram += "    C -->|Yes| D[Block IP]\n"
        diagram += "    C -->|No| E[Allow]\n"
        diagram += f"    D --> F[{blocked_ips} IPs Blocked]\n"
        diagram += "    E --> G[Server]\n"
        diagram += f"    B --> H[RPS: {current_rps:.1f}]"
        
        return diagram
    
    def generate_stats_chart(self, stats: Dict[str, Any]) -> str:
        """Generate simple stats visualization"""
        total = stats.get("total_requests", 0)
        success = stats.get("successful_requests", 0)
        blocked = stats.get("blocked_requests", 0)
        failed = stats.get("failed_requests", 0)
        
        # Simple flowchart showing stats
        diagram = f"""graph LR
    A[Total: {total}] --> B[Success: {success}]
    A --> C[Blocked: {blocked}]
    A --> D[Failed: {failed}]"""
        
        return diagram
    
    def generate_network_topology(self, nodes: List[Dict], connections: List[Dict]) -> str:
        """Generate simple network topology"""
        diagram_lines = ["graph LR"]
        
        # Add nodes with simple IDs
        for i, node in enumerate(nodes[:10]):  # Limit to 10 nodes for simplicity
            ip = node.get("ip", f"node{i}")
            # Use simple node names without special characters
            node_id = f"N{i}"
            diagram_lines.append(f"    {node_id}[{ip}]")
        
        # Add simple connections
        for conn in connections[:20]:  # Limit connections
            src = "N0"  # Simplified - just use first nodes
            dst = "N1"
            protocol = conn.get("protocol", "TCP")
            diagram_lines.append(f"    {src} --> {dst}")
        
        return "\n".join(diagram_lines)
    
    def generate_detection_timeline(self, events: List[str]) -> str:
        """Generate simple timeline"""
        diagram_lines = ["graph LR"]
        
        # Simple linear timeline
        for i, event in enumerate(events[:5]):  # Limit to 5 events
            if i == 0:
                diagram_lines.append(f"    A[{event}]")
            else:
                prev = chr(65 + i - 1)  # A, B, C, etc.
                curr = chr(65 + i)
                diagram_lines.append(f"    {prev} --> {curr}[{event}]")
        
        return "\n".join(diagram_lines)