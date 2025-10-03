"""
Test DDoS simulation system
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from attack_simulator import AttackSimulator
from storage.network_store import NetworkDataStore
from agents.mermaid_generator import MermaidGenerator
from agents.network_query_agent import NetworkQueryAgent

def test_ddos_simulation():
    print("💀 Testing DDoS Attack Simulation System\n")
    
    # Initialize components
    attack_sim = AttackSimulator()
    store = NetworkDataStore()
    mermaid_gen = MermaidGenerator()
    query_agent = NetworkQueryAgent(store)
    
    # 1. Generate DDoS attack
    print("1. Generating DDoS attack wave...")
    target_ip = "10.0.0.1"
    
    packets = attack_sim.generate_ddos_wave(
        target_ip=target_ip,
        target_port=80,
        wave_size=50,
        mixed_attack=True
    )
    
    print(f"✅ Generated {len(packets)} attack packets\n")
    
    # 2. Show attack statistics
    stats = attack_sim.generate_attack_statistics(packets)
    print("2. Attack Statistics:")
    print(f"   Total Packets: {stats['total_packets']}")
    print(f"   Total Bytes: {stats['total_bytes']:,}")
    print(f"   Unique Sources: {stats['unique_sources']}")
    print(f"   Bandwidth: {stats['bandwidth_mbps']:.2f} Mbps")
    print(f"   Attack Vector: {stats['attack_vector']}")
    print(f"   Severity: {stats['severity']}")
    print()
    
    print("   Top Protocols:")
    for protocol, count in stats['top_protocols']:
        print(f"      {protocol}: {count} packets")
    print()
    
    print("   Top Ports:")
    for port, count in stats['top_ports']:
        print(f"      Port {port}: {count} packets")
    print()
    
    # 3. Store in network store
    print("3. Storing attack data in network store...")
    for packet in packets:
        store.add_connection(
            src_ip=packet["src_ip"],
            dst_ip=packet["dst_ip"],
            protocol=packet["protocol"].lower(),
            port=packet["dst_port"],
            bytes=packet["size"],
            threat_level=packet["threat_level"]
        )
        
        # Add anomalies
        if packet.get("threats"):
            for threat in packet["threats"]:
                store.add_anomaly(
                    anomaly_type=threat["type"],
                    description=threat["description"],
                    severity=threat["severity"],
                    source=packet["src_ip"],
                    target=packet["dst_ip"]
                )
    
    store.save()
    print("✅ Data stored successfully\n")
    
    # 4. Query the attack data
    print("4. Testing queries on attack data...")
    
    test_queries = [
        "show recent anomalies",
        f"who is talking to {target_ip}",
        "what protocols are being used",
        "show threats"
    ]
    
    for query in test_queries:
        print(f"\n📝 Query: '{query}'")
        result = query_agent.query(query)
        
        if result["success"]:
            print(f"✅ Success - Type: {result.get('type', 'unknown')}")
            if result.get("data", {}).get("message"):
                print(f"   {result['data']['message']}")
    
    # 5. Generate Mermaid diagram
    print("\n5. Generating network attack visualization...")
    
    # Get all nodes and connections
    nodes = list(store.network_data["nodes"].values())[:20]  # Limit for readability
    connections = store.network_data["connections"][:30]  # Limit for readability
    
    diagram = mermaid_gen.generate_network_graph(nodes, connections, "DDoS Attack Visualization")
    
    print("📊 Mermaid Diagram (first 500 chars):")
    print(diagram[:500] + "..." if len(diagram) > 500 else diagram)
    
    print("\n✨ DDoS simulation test completed successfully!")
    
    # 6. Sample packets
    print("\n6. Sample Attack Packets:")
    for packet in packets[:5]:
        print(f"   {packet['id']}: {packet['src_ip']}:{packet['src_port']} -> {packet['dst_ip']}:{packet['dst_port']} [{packet['protocol']}] {packet['size']}B")

if __name__ == "__main__":
    test_ddos_simulation()