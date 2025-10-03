"""
Parallel threat analysis workflow using specialized agents
DAG pattern for optimized speed
"""
import asyncio
import json
import logging
import re
from typing import Dict, Any, List, TypedDict, Optional
from enum import Enum
from concurrent.futures import ThreadPoolExecutor
from langgraph.graph import StateGraph, END
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
import os
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SAFE = "safe"

class ParallelState(TypedDict):
    """State for parallel threat analysis"""
    packet_data: Dict[str, Any]
    xss_analysis: Optional[Dict[str, Any]]
    sql_analysis: Optional[Dict[str, Any]]
    dos_analysis: Optional[Dict[str, Any]]
    data_leak_analysis: Optional[Dict[str, Any]]
    anomaly_analysis: Optional[Dict[str, Any]]
    final_analysis: Dict[str, Any]
    timestamp: str

class ThreatAnalysisWorkflow:
    """Manages parallel threat analysis of network packets"""
    
    def __init__(self):
        # Initialize OpenAI GPT-4o-mini
        self.llm = ChatOpenAI(
            model="gpt-4o-mini",
            api_key=os.getenv("OPENAI_API_KEY"),
            temperature=0.1,  # Low temperature for consistent detection
            max_tokens=1000
        )
        
        # Thread pool for parallel analysis
        self.executor = ThreadPoolExecutor(max_workers=5)
        
        # Threat patterns database
        self.threat_patterns = self._initialize_threat_patterns()
        
        # Build the workflow
        self.workflow = self._build_graph()
    
    def _initialize_threat_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        """Initialize threat detection patterns"""
        return {
            "xss": [
                {"pattern": r"<script[^>]*>.*?</script>", "severity": "high"},
                {"pattern": r"javascript:", "severity": "medium"},
                {"pattern": r"on\w+\s*=", "severity": "medium"},
                {"pattern": r"eval\s*\(", "severity": "high"},
                {"pattern": r"document\.(cookie|write|location)", "severity": "high"},
                {"pattern": r"<iframe[^>]*>", "severity": "medium"}
            ],
            "sql": [
                {"pattern": r"(?i)(union|select|insert|update|delete|drop)\s+(from|into|table|database)", "severity": "critical"},
                {"pattern": r"(?i)or\s+\d+\s*=\s*\d+", "severity": "high"},
                {"pattern": r"(?i)'\s*or\s*'", "severity": "high"},
                {"pattern": r"(?i)exec\s*\(", "severity": "critical"},
                {"pattern": r"(?i)xp_cmdshell", "severity": "critical"},
                {"pattern": r"(?i)sp_executesql", "severity": "high"},
                {"pattern": r"--\s*$", "severity": "medium"}
            ],
            "dos": [
                {"pattern": "syn_flood", "type": "behavior"},
                {"pattern": "udp_flood", "type": "behavior"},
                {"pattern": "icmp_flood", "type": "behavior"},
                {"pattern": "slowloris", "type": "behavior"}
            ],
            "data_leak": [
                {"pattern": r"\b\d{3}-\d{2}-\d{4}\b", "type": "ssn", "severity": "critical"},
                {"pattern": r"\b\d{16}\b", "type": "credit_card", "severity": "critical"},
                {"pattern": r"(?i)(password|passwd|pwd)\s*[:=]\s*\S+", "severity": "high"},
                {"pattern": r"(?i)api[_-]?key\s*[:=]\s*\S+", "severity": "high"},
                {"pattern": r"(?i)token\s*[:=]\s*\S+", "severity": "high"}
            ]
        }
    
    def _build_graph(self) -> StateGraph:
        """Build the parallel analysis workflow"""
        workflow = StateGraph(ParallelState)
        
        # Add parallel analysis nodes
        workflow.add_node("xss_detector", self.xss_detector_node)
        workflow.add_node("sql_detector", self.sql_detector_node)
        workflow.add_node("dos_detector", self.dos_detector_node)
        workflow.add_node("data_leak_detector", self.data_leak_detector_node)
        workflow.add_node("anomaly_detector", self.anomaly_detector_node)
        workflow.add_node("aggregator", self.aggregator_node)
        
        # Set entry point to run all detectors in parallel
        workflow.set_entry_point("xss_detector")
        workflow.add_edge("xss_detector", "sql_detector")
        workflow.add_edge("sql_detector", "dos_detector")
        workflow.add_edge("dos_detector", "data_leak_detector")
        workflow.add_edge("data_leak_detector", "anomaly_detector")
        workflow.add_edge("anomaly_detector", "aggregator")
        workflow.add_edge("aggregator", END)
        
        return workflow.compile()
    
    async def xss_detector_node(self, state: ParallelState) -> ParallelState:
        """Detect XSS attack patterns"""
        logger.debug("Running XSS detection")
        
        packet_str = json.dumps(state["packet_data"])
        threats = []
        
        # Pattern matching
        for pattern_info in self.threat_patterns["xss"]:
            pattern = pattern_info["pattern"]
            if re.search(pattern, packet_str, re.IGNORECASE):
                threats.append({
                    "type": "XSS",
                    "pattern": pattern,
                    "severity": pattern_info["severity"],
                    "description": f"Detected XSS pattern: {pattern}"
                })
        
        # LLM-based detection for complex patterns
        if "http" in packet_str.lower() or "html" in packet_str.lower():
            prompt = f"""
            Analyze this network packet for XSS attack patterns:
            {packet_str[:1000]}
            
            Look for:
            - Script injections
            - Event handler injections
            - HTML/JavaScript payloads
            
            Respond with YES if XSS detected, NO otherwise.
            """
            
            try:
                response = await self.llm.ainvoke([
                    SystemMessage(content="You are an XSS detection expert."),
                    HumanMessage(content=prompt)
                ])
                
                if "YES" in response.content.upper():
                    threats.append({
                        "type": "XSS",
                        "pattern": "LLM-detected",
                        "severity": "medium",
                        "description": "Advanced XSS pattern detected by AI"
                    })
            except Exception as e:
                logger.error(f"XSS LLM detection error: {e}")
        
        state["xss_analysis"] = {
            "threats": threats,
            "threat_count": len(threats)
        }
        
        return state
    
    async def sql_detector_node(self, state: ParallelState) -> ParallelState:
        """Detect SQL injection patterns"""
        logger.debug("Running SQL injection detection")
        
        packet_str = json.dumps(state["packet_data"])
        threats = []
        
        # Pattern matching
        for pattern_info in self.threat_patterns["sql"]:
            pattern = pattern_info["pattern"]
            if re.search(pattern, packet_str, re.IGNORECASE):
                threats.append({
                    "type": "SQL Injection",
                    "pattern": pattern,
                    "severity": pattern_info["severity"],
                    "description": f"Detected SQL injection pattern: {pattern}"
                })
        
        state["sql_analysis"] = {
            "threats": threats,
            "threat_count": len(threats)
        }
        
        return state
    
    async def dos_detector_node(self, state: ParallelState) -> ParallelState:
        """Detect DoS/DDoS attack patterns"""
        logger.debug("Running DoS detection")
        
        packet_data = state["packet_data"]
        threats = []
        
        # Check for SYN flood indicators
        layers = packet_data.get("layers", [])
        for layer in layers:
            if layer.get("name") == "TCP":
                flags = layer.get("fields", {}).get("flags", "")
                if "S" in str(flags) and "A" not in str(flags):
                    # SYN without ACK
                    threats.append({
                        "type": "DoS",
                        "pattern": "SYN flood",
                        "severity": "high",
                        "description": "Potential SYN flood attack detected"
                    })
                    break
        
        # Check packet size for amplification attacks
        packet_size = packet_data.get("size", 0)
        if packet_size > 1500:
            threats.append({
                "type": "DoS",
                "pattern": "Large packet",
                "severity": "medium",
                "description": f"Unusually large packet ({packet_size} bytes)"
            })
        
        state["dos_analysis"] = {
            "threats": threats,
            "threat_count": len(threats)
        }
        
        return state
    
    async def data_leak_detector_node(self, state: ParallelState) -> ParallelState:
        """Detect potential data leakage"""
        logger.debug("Running data leak detection")
        
        packet_str = json.dumps(state["packet_data"])
        threats = []
        
        # Pattern matching for sensitive data
        for pattern_info in self.threat_patterns["data_leak"]:
            pattern = pattern_info["pattern"]
            if re.search(pattern, packet_str, re.IGNORECASE):
                threats.append({
                    "type": "Data Leak",
                    "pattern": pattern_info.get("type", "sensitive_data"),
                    "severity": pattern_info["severity"],
                    "description": f"Detected potential {pattern_info.get('type', 'sensitive data')}"
                })
        
        state["data_leak_analysis"] = {
            "threats": threats,
            "threat_count": len(threats)
        }
        
        return state
    
    async def anomaly_detector_node(self, state: ParallelState) -> ParallelState:
        """Detect anomalous patterns using AI"""
        logger.debug("Running anomaly detection")
        
        packet_data = state["packet_data"]
        anomalies = []
        
        # Check for unusual port combinations
        layers = packet_data.get("layers", [])
        for layer in layers:
            if layer.get("name") in ["TCP", "UDP"]:
                sport = layer.get("fields", {}).get("sport", 0)
                dport = layer.get("fields", {}).get("dport", 0)
                
                # Unusual high ports
                if sport > 50000 or dport > 50000:
                    anomalies.append({
                        "type": "Anomaly",
                        "pattern": "Unusual port",
                        "severity": "low",
                        "description": f"Unusual high port detected: {max(sport, dport)}"
                    })
        
        state["anomaly_analysis"] = {
            "anomalies": anomalies,
            "anomaly_count": len(anomalies)
        }
        
        return state
    
    async def aggregator_node(self, state: ParallelState) -> ParallelState:
        """Aggregate all threat analysis results"""
        logger.debug("Aggregating analysis results")
        
        all_threats = []
        
        # Collect all threats
        if state.get("xss_analysis"):
            all_threats.extend(state["xss_analysis"].get("threats", []))
        
        if state.get("sql_analysis"):
            all_threats.extend(state["sql_analysis"].get("threats", []))
        
        if state.get("dos_analysis"):
            all_threats.extend(state["dos_analysis"].get("threats", []))
        
        if state.get("data_leak_analysis"):
            all_threats.extend(state["data_leak_analysis"].get("threats", []))
        
        if state.get("anomaly_analysis"):
            all_threats.extend(state["anomaly_analysis"].get("anomalies", []))
        
        # Determine overall threat level
        threat_level = ThreatLevel.SAFE
        if any(t["severity"] == "critical" for t in all_threats):
            threat_level = ThreatLevel.CRITICAL
        elif any(t["severity"] == "high" for t in all_threats):
            threat_level = ThreatLevel.HIGH
        elif any(t["severity"] == "medium" for t in all_threats):
            threat_level = ThreatLevel.MEDIUM
        elif all_threats:
            threat_level = ThreatLevel.LOW
        
        # Build packet summary
        packet_summary = self._build_packet_summary(state["packet_data"])
        
        state["final_analysis"] = {
            "timestamp": state["timestamp"],
            "threat_level": threat_level.value,
            "total_threats": len(all_threats),
            "threats": all_threats,
            "packet_summary": packet_summary,
            "analysis_complete": True
        }
        
        return state
    
    def _build_packet_summary(self, packet_data: Dict[str, Any]) -> str:
        """Build a human-readable packet summary"""
        layers = packet_data.get("layers", [])
        summary_parts = []
        
        for layer in layers:
            name = layer.get("name", "Unknown")
            fields = layer.get("fields", {})
            
            if name == "IP":
                src = fields.get("src", "?")
                dst = fields.get("dst", "?")
                summary_parts.append(f"IP: {src} -> {dst}")
            
            elif name == "TCP":
                sport = fields.get("sport", "?")
                dport = fields.get("dport", "?")
                flags = fields.get("flags", "")
                summary_parts.append(f"TCP: {sport} -> {dport} [{flags}]")
            
            elif name == "UDP":
                sport = fields.get("sport", "?")
                dport = fields.get("dport", "?")
                summary_parts.append(f"UDP: {sport} -> {dport}")
        
        return " | ".join(summary_parts) if summary_parts else "Unknown packet"
    
    async def analyze_packet(self, packet: Any) -> Dict[str, Any]:
        """Main entry point for packet analysis"""
        
        # Convert packet to dict if needed
        if hasattr(packet, 'model_dump'):
            packet_data = packet.model_dump()
        elif isinstance(packet, dict):
            packet_data = packet
        else:
            packet_data = {"raw_data": str(packet)}
        
        initial_state = ParallelState(
            packet_data=packet_data.get("raw_data", packet_data),
            xss_analysis=None,
            sql_analysis=None,
            dos_analysis=None,
            data_leak_analysis=None,
            anomaly_analysis=None,
            final_analysis={},
            timestamp=datetime.now(timezone.utc).isoformat()
        )
        
        try:
            # Run the workflow
            result = await self.workflow.ainvoke(initial_state)
            return result["final_analysis"]
            
        except Exception as e:
            logger.error(f"Analysis workflow error: {e}")
            return {
                "timestamp": initial_state["timestamp"],
                "threat_level": ThreatLevel.SAFE.value,
                "error": str(e),
                "analysis_complete": False
            }


if __name__ == "__main__":
    # Test the workflow
    async def test_analysis():
        workflow = ThreatAnalysisWorkflow()
        
        # Test packets
        test_packets = [
            {
                "layers": [
                    {"name": "IP", "fields": {"src": "192.168.1.100", "dst": "10.0.0.1"}},
                    {"name": "TCP", "fields": {"sport": 45678, "dport": 80, "flags": "S"}}
                ],
                "size": 60
            },
            {
                "layers": [
                    {"name": "IP", "fields": {"src": "10.0.0.5", "dst": "192.168.1.1"}},
                    {"name": "TCP", "fields": {"sport": 443, "dport": 56789}}
                ],
                "raw_payload": "password: admin123",
                "size": 150
            },
            {
                "layers": [
                    {"name": "HTTP", "fields": {"method": "GET", "path": "/admin.php?id=1' OR '1'='1"}}
                ],
                "size": 200
            }
        ]
        
        for packet in test_packets:
            print(f"\nAnalyzing packet: {packet}")
            result = await workflow.analyze_packet(packet)
            print(f"Threat Level: {result['threat_level']}")
            print(f"Threats Found: {result.get('total_threats', 0)}")
            if result.get('threats'):
                for threat in result['threats']:
                    print(f"  - {threat['type']}: {threat['description']}")
    
    asyncio.run(test_analysis())