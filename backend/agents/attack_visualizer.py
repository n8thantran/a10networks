"""
Attack Visualization Generator - Creates Mermaid diagrams for DDoS attacks
"""
from typing import Dict, Any, List
from datetime import datetime
from .simple_mermaid import SimpleMermaidGenerator

class AttackVisualizer:
    """Generate visualizations for DDoS attacks and mitigations"""
    
    def __init__(self):
        self.simple_gen = SimpleMermaidGenerator()
    
    def generate_attack_flow_diagram(self, attack_data: Dict[str, Any]) -> str:
        """Generate attack flow visualization using simple syntax"""
        attack_type = attack_data.get("attack_type", "Unknown")
        stats = attack_data.get("stats", {})
        
        # Use the simple generator for guaranteed compatibility
        return self.simple_gen.generate_attack_flow(attack_type, stats)
    
    def generate_mitigation_diagram(self, mitigation_data: Dict[str, Any]) -> str:
        """Generate mitigation strategy visualization using simple syntax"""
        # Use simple generator for compatibility
        return self.simple_gen.generate_mitigation_flow(mitigation_data)
    
    def generate_mitigation_diagram_old(self, mitigation_data: Dict[str, Any]) -> str:
        """Old complex version - kept for reference"""
        mermaid = ["graph TB"]
        mermaid.append("    %% DDoS Mitigation Flow")
        
        # Incoming traffic
        mermaid.append("    TRAFFIC[Incoming Traffic]:::traffic")
        
        # Detection layers
        mermaid.append("    TRAFFIC --> FIREWALL[Firewall]:::defense")
        mermaid.append("    FIREWALL -->|Check IP| IPBLOCK{IP Blocked?}")
        
        mermaid.append("    IPBLOCK -->|Yes| DROPPED1[Drop Packet]:::dropped")
        mermaid.append("    IPBLOCK -->|No| RATELIMIT[Rate Limiter]:::defense")
        
        mermaid.append("    RATELIMIT -->|Check Rate| RATECHECK{Rate OK?}")
        mermaid.append("    RATECHECK -->|No| DROPPED2[Drop Packet]:::dropped")
        mermaid.append("    RATECHECK -->|Yes| AIAGENT[AI Agent]:::ai")
        
        # AI Analysis
        mermaid.append("    AIAGENT -->|Analyze| THREAT{Threat?}")
        mermaid.append("    THREAT -->|High| BLOCK[Block & Log]:::action")
        mermaid.append("    THREAT -->|Medium| THROTTLE[Throttle]:::action")
        mermaid.append("    THREAT -->|Low| MONITOR[Monitor]:::action")
        mermaid.append("    THREAT -->|None| ALLOW[Allow]:::success")
        
        # Actions
        mermaid.append("    BLOCK --> DROPPED3[Drop Packet]:::dropped")
        mermaid.append("    THROTTLE --> QUEUE[Queue]:::action")
        mermaid.append("    MONITOR --> LOG[Log]:::action")
        mermaid.append("    ALLOW --> SERVER[Server]:::success")
        mermaid.append("    QUEUE --> SERVER")
        mermaid.append("    LOG --> SERVER")
        
        # Blocked IPs count
        blocked_count = mitigation_data.get("blocked_count", 0)
        if blocked_count > 0:
            mermaid.append(f"    STATS[Blocked IPs: {blocked_count}]:::stats")
            mermaid.append("    DROPPED1 -.-> STATS")
            mermaid.append("    DROPPED2 -.-> STATS")
            mermaid.append("    DROPPED3 -.-> STATS")
        
        # Styles
        mermaid.extend([
            "    classDef traffic fill:#ff9,stroke:#cc0,stroke-width:2px",
            "    classDef defense fill:#9cf,stroke:#369,stroke-width:2px",
            "    classDef ai fill:#c9f,stroke:#639,stroke-width:3px",
            "    classDef dropped fill:#f99,stroke:#c33,stroke-width:2px",
            "    classDef action fill:#fc9,stroke:#c63,stroke-width:2px",
            "    classDef success fill:#9f9,stroke:#393,stroke-width:2px",
            "    classDef stats fill:#ccc,stroke:#666,stroke-width:1px"
        ])
        
        return "\n".join(mermaid)
    
    def generate_timeline_diagram(self, events: List[Dict[str, Any]]) -> str:
        """Generate attack timeline"""
        mermaid = ["sequenceDiagram"]
        mermaid.append("    participant Attacker")
        mermaid.append("    participant Firewall")
        mermaid.append("    participant AI as AI Agent")
        mermaid.append("    participant Server")
        
        for event in events[-20:]:  # Last 20 events
            event_type = event.get("type", "unknown")
            
            if "attack" in event_type.lower():
                mermaid.append(f"    Attacker->>Firewall: {event_type}")
            elif "block" in event.get("action", "").lower():
                mermaid.append(f"    Firewall--xAttacker: Block {event.get('target', 'IP')}")
            elif "detect" in event_type.lower():
                mermaid.append(f"    AI->>Firewall: Threat Detected")
            elif "allow" in event.get("action", "").lower():
                mermaid.append(f"    Firewall->>Server: Forward Traffic")
            
        return "\n".join(mermaid)
    
    def generate_statistics_diagram(self, stats: Dict[str, Any]) -> str:
        """Generate statistics visualization using simple syntax"""
        # Use simple generator for compatibility
        return self.simple_gen.generate_stats_chart(stats)
    
    def generate_statistics_diagram_old(self, stats: Dict[str, Any]) -> str:
        """Old complex version - kept for reference"""
        mermaid = ["graph LR"]
        mermaid.append("    %% Attack Statistics")
        
        # Stats boxes
        total_requests = stats.get("total_requests", 0)
        blocked = stats.get("blocked_requests", 0)
        success = stats.get("successful_requests", 0)
        failed = stats.get("failed_requests", 0)
        
        mermaid.append(f"    TOTAL[Total Requests<br/>{total_requests}]:::total")
        mermaid.append(f"    BLOCKED[Blocked<br/>{blocked}]:::blocked")
        mermaid.append(f"    SUCCESS[Successful<br/>{success}]:::success")
        mermaid.append(f"    FAILED[Failed<br/>{failed}]:::failed")
        
        # Flow
        mermaid.append("    TOTAL --> BLOCKED")
        mermaid.append("    TOTAL --> SUCCESS")
        mermaid.append("    TOTAL --> FAILED")
        
        # RPS meter
        current_rps = stats.get("current_rps", 0)
        baseline_rps = stats.get("baseline_rps", 10)
        
        if current_rps > baseline_rps * 3:
            rps_status = "CRITICAL"
            rps_class = "critical"
        elif current_rps > baseline_rps * 2:
            rps_status = "WARNING"
            rps_class = "warning"
        else:
            rps_status = "NORMAL"
            rps_class = "normal"
        
        mermaid.append(f"    RPS[RPS: {current_rps:.1f}<br/>Status: {rps_status}]:::{rps_class}")
        mermaid.append("    SUCCESS --> RPS")
        
        # Styles
        mermaid.extend([
            "    classDef total fill:#99f,stroke:#33f,stroke-width:2px",
            "    classDef blocked fill:#f99,stroke:#f33,stroke-width:2px",
            "    classDef success fill:#9f9,stroke:#3f3,stroke-width:2px",
            "    classDef failed fill:#ff9,stroke:#cc3,stroke-width:2px",
            "    classDef critical fill:#f00,stroke:#900,stroke-width:3px",
            "    classDef warning fill:#fc0,stroke:#c90,stroke-width:2px",
            "    classDef normal fill:#0f0,stroke:#090,stroke-width:2px"
        ])
        
        return "\n".join(mermaid)
    
    def generate_attack_explanation(self, attack_data: Dict[str, Any], mitigation_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive attack explanation"""
        attack_type = attack_data.get("attack_type", "Unknown")
        
        explanations = {
            "Volumetric Flood": {
                "description": "A volumetric DDoS attack floods the target with massive amounts of traffic, exhausting bandwidth and resources.",
                "how_it_works": [
                    "Attackers send large volumes of UDP, TCP, or ICMP packets",
                    "Network bandwidth becomes saturated",
                    "Legitimate users cannot reach the service"
                ],
                "indicators": [
                    "Sudden spike in traffic (3x+ normal)",
                    "High packet rate from multiple sources",
                    "Bandwidth exhaustion"
                ]
            },
            "Slowloris": {
                "description": "Slowloris attacks keep many connections open with minimal data, exhausting server connection pools.",
                "how_it_works": [
                    "Open multiple connections to the target",
                    "Send partial HTTP requests very slowly",
                    "Keep connections alive but incomplete",
                    "Exhaust server's connection pool"
                ],
                "indicators": [
                    "Many half-open connections",
                    "Slow data transmission rates",
                    "Connection timeouts"
                ]
            },
            "Application Layer": {
                "description": "Application layer attacks target specific web applications with complex requests that consume server resources.",
                "how_it_works": [
                    "Send legitimate-looking but resource-intensive requests",
                    "Exploit application vulnerabilities (SQL injection, XSS)",
                    "Overwhelm backend services and databases"
                ],
                "indicators": [
                    "Complex query patterns",
                    "Repeated failed authentication attempts",
                    "Database performance degradation"
                ]
            },
            "Multi-Vector": {
                "description": "Multi-vector attacks combine multiple DDoS techniques simultaneously for maximum impact.",
                "how_it_works": [
                    "Combine volumetric, protocol, and application attacks",
                    "Target multiple layers of infrastructure",
                    "Adapt tactics based on defenses"
                ],
                "indicators": [
                    "Multiple attack patterns simultaneously",
                    "Varied packet types and sizes",
                    "Coordinated from multiple sources"
                ]
            }
        }
        
        explanation = explanations.get(attack_type, {
            "description": "Unknown attack type detected",
            "how_it_works": ["Attack pattern not recognized"],
            "indicators": ["Anomalous traffic patterns"]
        })
        
        # Add mitigation explanation
        mitigation_explanation = {
            "actions_taken": [],
            "effectiveness": "Not measured"
        }
        
        if mitigation_data.get("mitigation_active"):
            mitigation_explanation["actions_taken"] = [
                f"Blocked {mitigation_data.get('blocked_count', 0)} malicious IPs",
                f"Applied {len(mitigation_data.get('mitigation_rules', []))} firewall rules",
                "Activated rate limiting",
                "AI agent analyzing traffic patterns"
            ]
            
            blocked = mitigation_data.get("metrics", {}).get("blocked_requests", 0)
            total = attack_data.get("stats", {}).get("total_requests", 1)
            effectiveness = (blocked / total * 100) if total > 0 else 0
            
            mitigation_explanation["effectiveness"] = f"{effectiveness:.1f}% of malicious traffic blocked"
        
        return {
            "attack_type": attack_type,
            "explanation": explanation,
            "mitigation": mitigation_explanation,
            "statistics": {
                "total_requests": attack_data.get("stats", {}).get("total_requests", 0),
                "blocked_requests": mitigation_data.get("metrics", {}).get("blocked_requests", 0),
                "attack_duration": attack_data.get("stats", {}).get("duration", 0),
                "data_transmitted": f"{attack_data.get('stats', {}).get('bytes_sent', 0) / 1024:.2f} KB"
            },
            "recommendations": [
                "Enable DDoS protection permanently",
                "Configure rate limiting rules",
                "Set up traffic monitoring alerts",
                "Implement CAPTCHA for suspicious requests",
                "Use CDN for traffic distribution"
            ]
        }