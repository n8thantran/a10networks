"""
Attack simulation module for demonstration purposes
WARNING: This is for educational and defensive security demonstration only
"""
import random
import asyncio
from typing import Dict, Any, List
from datetime import datetime, timezone
import uuid

class AttackSimulator:
    """Simulates various network attacks for defensive testing"""
    
    def __init__(self):
        self.attack_patterns = {
            "ddos": self._generate_ddos_packet,
            "port_scan": self._generate_port_scan_packet,
            "syn_flood": self._generate_syn_flood_packet,
            "slowloris": self._generate_slowloris_packet,
            "dns_amplification": self._generate_dns_amplification_packet
        }
        
        # Common target ports for DDoS
        self.common_ports = [80, 443, 22, 21, 25, 53, 110, 143, 3306, 3389, 8080, 8443]
        
        # Bot network IPs for simulation
        self.botnet_ranges = [
            "192.168.", "10.0.", "172.16.", 
            "45.142.", "185.220.", "209.141.",
            "23.129.", "198.98.", "51.75."
        ]
    
    def _generate_random_ip(self, use_botnet: bool = True) -> str:
        """Generate a random IP address"""
        if use_botnet and random.random() > 0.3:
            prefix = random.choice(self.botnet_ranges)
            if prefix.startswith("192.168."):
                return f"{prefix}{random.randint(1, 254)}.{random.randint(1, 254)}"
            elif prefix.startswith("10.0."):
                return f"{prefix}{random.randint(0, 255)}.{random.randint(1, 254)}"
            else:
                return f"{prefix}{random.randint(0, 255)}.{random.randint(1, 254)}"
        else:
            return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    
    def _generate_ddos_packet(self, target_ip: str, target_port: int = None) -> Dict[str, Any]:
        """Generate a DDoS attack packet"""
        if target_port is None:
            target_port = random.choice(self.common_ports)
        
        source_ip = self._generate_random_ip()
        source_port = random.randint(1024, 65535)
        
        # Simulate different DDoS attack types
        attack_types = ["SYN", "UDP", "HTTP", "ICMP", "DNS"]
        attack_type = random.choice(attack_types)
        
        packet_size = random.choice([64, 128, 256, 512, 1024, 1500, 4096, 8192])
        
        return {
            "id": f"DDOS-{str(uuid.uuid4())[:8]}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": source_ip,
            "dst_ip": target_ip,
            "src_port": source_port,
            "dst_port": target_port,
            "protocol": attack_type,
            "size": packet_size,
            "flags": "SYN" if attack_type == "SYN" else None,
            "threat_level": "critical",
            "attack_type": "DDoS",
            "threats": [{
                "type": "DDoS Attack",
                "severity": "critical",
                "pattern": f"{attack_type} Flood",
                "description": f"Part of distributed denial-of-service attack"
            }]
        }
    
    def _generate_syn_flood_packet(self, target_ip: str, target_port: int = None) -> Dict[str, Any]:
        """Generate a SYN flood packet"""
        if target_port is None:
            target_port = random.choice([80, 443, 22])
        
        return {
            "id": f"SYN-{str(uuid.uuid4())[:8]}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": self._generate_random_ip(),
            "dst_ip": target_ip,
            "src_port": random.randint(1024, 65535),
            "dst_port": target_port,
            "protocol": "TCP",
            "size": 64,
            "flags": "SYN",
            "threat_level": "critical",
            "attack_type": "SYN Flood",
            "threats": [{
                "type": "SYN Flood",
                "severity": "critical",
                "pattern": "TCP SYN without ACK",
                "description": "Half-open connection attack"
            }]
        }
    
    def _generate_port_scan_packet(self, target_ip: str, target_port: int = None) -> Dict[str, Any]:
        """Generate a port scan packet"""
        scanner_ip = self._generate_random_ip(use_botnet=False)
        
        return {
            "id": f"SCAN-{str(uuid.uuid4())[:8]}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": scanner_ip,
            "dst_ip": target_ip,
            "src_port": random.randint(40000, 65535),
            "dst_port": target_port if target_port else random.randint(1, 65535),
            "protocol": "TCP",
            "size": 40,
            "flags": random.choice(["SYN", "FIN", "NULL", "XMAS"]),
            "threat_level": "high",
            "attack_type": "Port Scan",
            "threats": [{
                "type": "Port Scan",
                "severity": "high",
                "pattern": "Sequential port probing",
                "description": "Reconnaissance activity detected"
            }]
        }
    
    def _generate_slowloris_packet(self, target_ip: str, target_port: int = 80) -> Dict[str, Any]:
        """Generate a Slowloris attack packet"""
        return {
            "id": f"SLOW-{str(uuid.uuid4())[:8]}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": self._generate_random_ip(),
            "dst_ip": target_ip,
            "src_port": random.randint(40000, 65535),
            "dst_port": target_port,
            "protocol": "HTTP",
            "size": random.randint(100, 300),
            "threat_level": "high",
            "attack_type": "Slowloris",
            "threats": [{
                "type": "Slowloris Attack",
                "severity": "high",
                "pattern": "Incomplete HTTP headers",
                "description": "Slow HTTP DoS attack keeping connections open"
            }]
        }
    
    def _generate_dns_amplification_packet(self, target_ip: str, target_port: int = 53) -> Dict[str, Any]:
        """Generate a DNS amplification attack packet"""
        dns_server = f"8.8.{random.randint(4, 8)}.{random.randint(1, 254)}"
        
        return {
            "id": f"DNS-{str(uuid.uuid4())[:8]}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": dns_server,
            "dst_ip": target_ip,
            "src_port": 53,
            "dst_port": random.randint(1024, 65535),
            "protocol": "DNS",
            "size": random.randint(500, 4096),
            "threat_level": "critical",
            "attack_type": "DNS Amplification",
            "threats": [{
                "type": "DNS Amplification",
                "severity": "critical",
                "pattern": "Large DNS response",
                "description": "Reflected DNS amplification attack"
            }]
        }
    
    def generate_ddos_wave(self, target_ip: str, target_port: int = None, 
                          wave_size: int = 50, mixed_attack: bool = True) -> List[Dict[str, Any]]:
        """Generate a wave of DDoS packets"""
        packets = []
        
        for _ in range(wave_size):
            if mixed_attack and random.random() > 0.7:
                # Mix in different attack types
                attack_type = random.choice(["syn_flood", "port_scan", "slowloris", "dns_amplification"])
                packet_gen = self.attack_patterns.get(attack_type, self._generate_ddos_packet)
            else:
                packet_gen = self._generate_ddos_packet
            
            packet = packet_gen(target_ip, target_port)
            packets.append(packet)
        
        return packets
    
    def generate_attack_statistics(self, packets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate statistics from attack packets"""
        if not packets:
            return {}
        
        total_bytes = sum(p.get("size", 0) for p in packets)
        unique_sources = len(set(p.get("src_ip") for p in packets))
        protocols = {}
        ports = {}
        
        for packet in packets:
            protocol = packet.get("protocol", "Unknown")
            protocols[protocol] = protocols.get(protocol, 0) + 1
            
            port = packet.get("dst_port")
            if port:
                ports[port] = ports.get(port, 0) + 1
        
        return {
            "total_packets": len(packets),
            "total_bytes": total_bytes,
            "unique_sources": unique_sources,
            "packets_per_second": len(packets),  # Simulated as instant
            "bandwidth_mbps": (total_bytes * 8) / 1_000_000,  # Convert to Mbps
            "top_protocols": sorted(protocols.items(), key=lambda x: x[1], reverse=True)[:5],
            "top_ports": sorted(ports.items(), key=lambda x: x[1], reverse=True)[:5],
            "attack_vector": "Distributed" if unique_sources > 10 else "Single Source",
            "severity": "CRITICAL" if len(packets) > 30 else "HIGH"
        }