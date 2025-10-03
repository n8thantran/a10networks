"""
AI Agent for DDoS Detection and Mitigation
"""
import asyncio
from typing import Dict, Any, List, Optional, Set
from datetime import datetime, timedelta
from collections import defaultdict, deque
import statistics
import json
import hashlib

class DDoSProtectionAgent:
    """AI-powered DDoS detection and mitigation system"""
    
    def __init__(self):
        # Traffic analysis windows
        self.traffic_window = deque(maxlen=1000)  # Last 1000 packets
        self.time_window = 60  # seconds
        
        # Connection tracking
        self.connections = defaultdict(lambda: {
            "count": 0,
            "last_seen": datetime.now(),
            "bytes": 0,
            "patterns": [],
            "blocked": False
        })
        
        # Rate limiting
        self.rate_limits = {
            "global": 50,  # requests per second - LOWERED for faster detection
            "per_ip": 10,   # requests per IP per second - LOWERED
            "connection": 5  # new connections per IP per second - LOWERED
        }
        
        # Threat detection thresholds - MORE SENSITIVE
        self.thresholds = {
            "traffic_spike": 2.0,  # 2x normal traffic - LOWERED
            "connection_rate": 20,  # connections per second - LOWERED
            "packet_size_anomaly": 1.5,  # std deviations - LOWERED
            "pattern_similarity": 0.6,  # pattern matching threshold - LOWERED
            "slowloris_timeout": 10  # seconds for slow connections - LOWERED
        }
        
        # Blocked IPs and patterns
        self.blocked_ips: Set[str] = set()
        self.blocked_patterns: List[str] = []
        
        # Attack detection state
        self.attack_detected = False
        self.attack_type = None
        self.attack_start = None
        self.mitigation_active = False
        self.mitigation_rules = []
        
        # Metrics
        self.metrics = {
            "baseline_rps": 10,
            "current_rps": 0,
            "blocked_requests": 0,
            "detected_attacks": 0,
            "false_positives": 0
        }
        
        # ML-based pattern detection
        self.packet_patterns = deque(maxlen=100)
        self.normal_behavior = {
            "avg_packet_size": 500,
            "avg_rps": 10,
            "connection_duration": 5,
            "unique_ips_per_minute": 20
        }
    
    async def analyze_traffic(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze incoming traffic for DDoS patterns"""
        analysis_result = {
            "timestamp": datetime.now().isoformat(),
            "packet_id": packet.get("id"),
            "threat_detected": False,
            "threat_type": None,
            "confidence": 0,
            "action": "allow",
            "details": {}
        }
        
        # Add to traffic window
        self.traffic_window.append({
            "timestamp": datetime.now(),
            "packet": packet
        })
        
        # Extract packet info
        src_ip = packet.get("src_ip", "unknown")
        packet_size = packet.get("size", 0)
        protocol = packet.get("protocol", "").lower()
        
        # Update connection tracking
        self.connections[src_ip]["count"] += 1
        self.connections[src_ip]["last_seen"] = datetime.now()
        self.connections[src_ip]["bytes"] += packet_size
        
        # Check if IP is blocked
        if src_ip in self.blocked_ips:
            analysis_result["threat_detected"] = True
            analysis_result["threat_type"] = "blocked_ip"
            analysis_result["action"] = "block"
            analysis_result["confidence"] = 1.0
            self.metrics["blocked_requests"] += 1
            return analysis_result
        
        # Run detection algorithms
        detections = []
        
        # 1. Volume-based detection
        volume_threat = self._detect_volumetric_attack()
        if volume_threat["detected"]:
            detections.append(volume_threat)
            # Set attack detected flag immediately
            self.attack_detected = True
            self.attack_type = "volumetric"
        
        # 2. Pattern-based detection
        pattern_threat = self._detect_pattern_anomaly(packet)
        if pattern_threat["detected"]:
            detections.append(pattern_threat)
        
        # 3. Behavioral analysis
        behavior_threat = self._detect_behavioral_anomaly(src_ip)
        if behavior_threat["detected"]:
            detections.append(behavior_threat)
            # Set attack detected for rate limit violations
            if behavior_threat["type"] == "rate_limit_exceeded":
                self.attack_detected = True
                if not self.attack_type:
                    self.attack_type = "rate_limit"
        
        # 4. Protocol-specific detection
        protocol_threat = self._detect_protocol_attack(packet)
        if protocol_threat["detected"]:
            detections.append(protocol_threat)
        
        # Aggregate detection results
        if detections:
            # Calculate overall confidence
            avg_confidence = statistics.mean([d["confidence"] for d in detections])
            
            if avg_confidence > 0.5:  # Lower threshold for faster detection
                self.attack_detected = True
                analysis_result["threat_detected"] = True
                analysis_result["threat_type"] = detections[0]["type"]
                analysis_result["confidence"] = avg_confidence
                analysis_result["details"] = {
                    "detections": detections,
                    "src_ip": src_ip
                }
                
                # Determine action
                if avg_confidence > 0.7:  # Lower threshold
                    analysis_result["action"] = "block"
                    await self._apply_mitigation(src_ip, detections[0]["type"])
                elif avg_confidence > 0.5:
                    analysis_result["action"] = "throttle"
                else:
                    analysis_result["action"] = "monitor"
        
        return analysis_result
    
    def _detect_volumetric_attack(self) -> Dict[str, Any]:
        """Detect volume-based DDoS attacks"""
        current_time = datetime.now()
        
        # Calculate RPS over last 5 seconds for more responsive detection
        recent_packets = [
            p for p in self.traffic_window
            if (current_time - p["timestamp"]).total_seconds() < 5
        ]
        
        # More accurate RPS calculation
        time_window = 5  # seconds
        current_rps = len(recent_packets) / time_window if len(recent_packets) > 0 else 0
        self.metrics["current_rps"] = current_rps
        
        # Dynamic baseline adjustment - but not during attacks
        if not self.attack_detected and current_rps > 0:
            # Slowly adjust baseline if traffic is normal
            self.metrics["baseline_rps"] = min(self.metrics["baseline_rps"] * 0.9 + current_rps * 0.1, 20)
        
        # Check for traffic spike - lower threshold for faster detection
        if current_rps > max(self.metrics["baseline_rps"] * self.thresholds["traffic_spike"], 20):
            spike_factor = current_rps / max(self.metrics["baseline_rps"], 1)
            return {
                "detected": True,
                "type": "volumetric",
                "confidence": min(spike_factor / 3, 1.0),  # High confidence at 3x baseline
                "details": {
                    "current_rps": current_rps,
                    "baseline_rps": self.metrics["baseline_rps"],
                    "spike_factor": spike_factor
                }
            }
        
        return {"detected": False}
    
    def _detect_pattern_anomaly(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        """Detect pattern-based anomalies using ML"""
        # Extract packet features
        features = {
            "size": packet.get("size", 0),
            "protocol": packet.get("protocol", ""),
            "port": packet.get("dst_port", 0)
        }
        
        # Simple anomaly detection based on packet size
        avg_size = self.normal_behavior["avg_packet_size"]
        size_deviation = abs(features["size"] - avg_size) / avg_size if avg_size > 0 else 0
        
        if size_deviation > self.thresholds["packet_size_anomaly"]:
            return {
                "detected": True,
                "type": "pattern_anomaly",
                "confidence": min(size_deviation / 5, 1.0),
                "details": {
                    "packet_size": features["size"],
                    "expected_size": avg_size,
                    "deviation": size_deviation
                }
            }
        
        # Check for repetitive patterns
        packet_hash = hashlib.md5(json.dumps(features, sort_keys=True).encode()).hexdigest()
        self.packet_patterns.append(packet_hash)
        
        if len(self.packet_patterns) >= 10:
            pattern_count = self.packet_patterns.count(packet_hash)
            if pattern_count > len(self.packet_patterns) * 0.5:
                return {
                    "detected": True,
                    "type": "pattern_repetition",
                    "confidence": pattern_count / len(self.packet_patterns),
                    "details": {
                        "pattern_hash": packet_hash,
                        "repetition_rate": pattern_count / len(self.packet_patterns)
                    }
                }
        
        return {"detected": False}
    
    def _detect_behavioral_anomaly(self, src_ip: str) -> Dict[str, Any]:
        """Detect behavioral anomalies from specific IPs"""
        conn_info = self.connections[src_ip]
        
        # Check connection rate
        if conn_info["count"] > self.rate_limits["per_ip"]:
            return {
                "detected": True,
                "type": "rate_limit_exceeded",
                "confidence": min(conn_info["count"] / (self.rate_limits["per_ip"] * 2), 1.0),
                "details": {
                    "ip": src_ip,
                    "request_count": conn_info["count"],
                    "limit": self.rate_limits["per_ip"]
                }
            }
        
        # Check for slowloris pattern
        connection_age = (datetime.now() - conn_info["last_seen"]).total_seconds()
        if conn_info["count"] < 5 and connection_age > self.thresholds["slowloris_timeout"]:
            return {
                "detected": True,
                "type": "slowloris",
                "confidence": 0.8,
                "details": {
                    "ip": src_ip,
                    "connection_age": connection_age,
                    "packet_count": conn_info["count"]
                }
            }
        
        return {"detected": False}
    
    def _detect_protocol_attack(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        """Detect protocol-specific attacks"""
        protocol = packet.get("protocol", "").lower()
        
        # SYN flood detection
        if protocol == "tcp":
            flags = packet.get("flags", "")
            if "SYN" in str(flags) and "ACK" not in str(flags):
                # Count SYN packets
                syn_count = sum(
                    1 for p in self.traffic_window
                    if "SYN" in str(p.get("packet", {}).get("flags", ""))
                )
                
                if syn_count > 100:  # Threshold for SYN flood
                    return {
                        "detected": True,
                        "type": "syn_flood",
                        "confidence": min(syn_count / 200, 1.0),
                        "details": {
                            "syn_count": syn_count,
                            "protocol": protocol
                        }
                    }
        
        # DNS amplification detection
        elif protocol == "udp" and packet.get("dst_port") == 53:
            if packet.get("size", 0) < 100:  # Small DNS query
                return {
                    "detected": True,
                    "type": "dns_amplification",
                    "confidence": 0.7,
                    "details": {
                        "protocol": protocol,
                        "port": 53,
                        "packet_size": packet.get("size", 0)
                    }
                }
        
        return {"detected": False}
    
    async def _apply_mitigation(self, src_ip: str, attack_type: str):
        """Apply mitigation strategies"""
        if not self.mitigation_active:
            self.mitigation_active = True
            self.attack_start = datetime.now()
            self.attack_type = attack_type
            self.metrics["detected_attacks"] += 1
        
        # Block the offending IP
        self.blocked_ips.add(src_ip)
        
        # Add mitigation rule
        rule = {
            "timestamp": datetime.now().isoformat(),
            "action": "block",
            "target": src_ip,
            "reason": attack_type,
            "duration": 3600  # Block for 1 hour
        }
        self.mitigation_rules.append(rule)
        
        # Log mitigation action
        print(f"🛡️ Mitigation applied: Blocked {src_ip} for {attack_type}")
    
    def get_mitigation_status(self) -> Dict[str, Any]:
        """Get current mitigation status and statistics"""
        status = {
            "protection_active": True,
            "attack_detected": self.attack_detected,
            "mitigation_active": self.mitigation_active,
            "attack_type": self.attack_type,
            "attack_start": self.attack_start.isoformat() if self.attack_start else None,
            "blocked_ips": list(self.blocked_ips),
            "blocked_count": len(self.blocked_ips),
            "mitigation_rules": self.mitigation_rules[-10:],  # Last 10 rules
            "metrics": self.metrics,
            "current_rps": self.metrics["current_rps"],
            "baseline_rps": self.metrics["baseline_rps"]
        }
        
        if self.mitigation_active and self.attack_start:
            status["attack_duration"] = (datetime.now() - self.attack_start).total_seconds()
        
        return status
    
    def reset_mitigation(self):
        """Reset mitigation state"""
        self.blocked_ips.clear()
        self.mitigation_rules.clear()
        self.mitigation_active = False
        self.attack_detected = False
        self.attack_type = None
        self.attack_start = None
        print("🔄 Mitigation rules reset")
    
    def update_baseline(self):
        """Update baseline metrics for normal traffic"""
        if not self.attack_detected and len(self.traffic_window) > 100:
            recent_packets = list(self.traffic_window)[-100:]
            
            # Calculate new baseline
            packet_sizes = [p["packet"].get("size", 0) for p in recent_packets]
            self.normal_behavior["avg_packet_size"] = statistics.mean(packet_sizes) if packet_sizes else 500
            
            # Update baseline RPS
            time_span = (recent_packets[-1]["timestamp"] - recent_packets[0]["timestamp"]).total_seconds()
            if time_span > 0:
                self.metrics["baseline_rps"] = len(recent_packets) / time_span
    
    def generate_attack_report(self) -> Dict[str, Any]:
        """Generate comprehensive attack analysis report"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_attacks_detected": self.metrics["detected_attacks"],
                "total_requests_blocked": self.metrics["blocked_requests"],
                "active_mitigations": len(self.mitigation_rules),
                "blocked_ips": len(self.blocked_ips)
            },
            "current_attack": None,
            "top_attackers": [],
            "attack_timeline": [],
            "effectiveness": {}
        }
        
        if self.attack_detected:
            report["current_attack"] = {
                "type": self.attack_type,
                "started": self.attack_start.isoformat() if self.attack_start else None,
                "duration": (datetime.now() - self.attack_start).total_seconds() if self.attack_start else 0,
                "mitigated": self.mitigation_active
            }
        
        # Top attackers
        top_ips = sorted(
            self.connections.items(),
            key=lambda x: x[1]["count"],
            reverse=True
        )[:5]
        
        report["top_attackers"] = [
            {
                "ip": ip,
                "requests": info["count"],
                "bytes": info["bytes"],
                "blocked": ip in self.blocked_ips
            }
            for ip, info in top_ips
        ]
        
        # Attack timeline
        for rule in self.mitigation_rules[-10:]:
            report["attack_timeline"].append({
                "time": rule["timestamp"],
                "action": rule["action"],
                "target": rule["target"],
                "reason": rule["reason"]
            })
        
        # Calculate effectiveness
        if self.metrics["detected_attacks"] > 0:
            report["effectiveness"] = {
                "detection_rate": "High" if self.metrics["detected_attacks"] > 0 else "N/A",
                "mitigation_rate": f"{(self.metrics['blocked_requests'] / max(self.metrics['current_rps'] * 60, 1)) * 100:.2f}%",
                "false_positive_rate": f"{(self.metrics['false_positives'] / max(self.metrics['detected_attacks'], 1)) * 100:.2f}%"
            }
        
        return report