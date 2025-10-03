"""
Test the network query and visualization system
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from storage.network_store import NetworkDataStore
from agents.network_query_agent import NetworkQueryAgent
from agents.mermaid_generator import MermaidGenerator

def test_system():
    print("🔬 Testing Network Query and Visualization System\n")
    
    # Initialize components
    store = NetworkDataStore()
    query_agent = NetworkQueryAgent(store)
    mermaid_gen = MermaidGenerator()
    
    # 1. Add test network data
    print("1. Adding test network data...")
    
    # Add nodes
    store.add_node("192.168.1.1", hostname="router", type="router", mac="00:11:22:33:44:55")
    store.add_node("192.168.1.100", hostname="workstation1", type="host", os="Windows 10")
    store.add_node("192.168.1.101", hostname="workstation2", type="host", os="Ubuntu")
    store.add_node("192.168.1.200", hostname="server1", type="server", os="Ubuntu Server")
    store.add_node("10.0.0.1", hostname="firewall", type="firewall")
    store.add_node("8.8.8.8", hostname="dns.google", type="server")
    
    # Add connections
    store.add_connection("192.168.1.100", "192.168.1.200", "tcp", 443, bytes=1024, service="HTTPS")
    store.add_connection("192.168.1.101", "192.168.1.200", "tcp", 22, bytes=2048, service="SSH")
    store.add_connection("192.168.1.100", "8.8.8.8", "udp", 53, bytes=128, service="DNS")
    store.add_connection("192.168.1.101", "8.8.8.8", "udp", 53, bytes=128, service="DNS")
    store.add_connection("192.168.1.200", "10.0.0.1", "tcp", 80, bytes=4096, service="HTTP")
    
    # Add services
    store.add_service("192.168.1.200", 443, "nginx", version="1.18.0")
    store.add_service("192.168.1.200", 22, "openssh", version="8.2p1")
    store.add_service("192.168.1.1", 80, "web-admin", product="Router Admin Panel")
    
    # Add some anomalies
    store.add_anomaly("Port Scan", "Multiple port connection attempts detected", 
                     severity="high", source="192.168.1.101", target="192.168.1.200")
    store.add_anomaly("SQL Injection", "SQL injection pattern detected in HTTP request",
                     severity="critical", source="192.168.1.100", target="192.168.1.200")
    
    # Save data
    store.save()
    print("✅ Test data added successfully\n")
    
    # 2. Test queries
    print("2. Testing natural language queries...\n")
    
    test_queries = [
        "show all nodes",
        "what is the network topology",
        "show connections from 192.168.1.100",
        "what protocols are being used",
        "show recent anomalies",
        "who is talking to 192.168.1.200",
        "show services on 192.168.1.200",
        "show tcp connections"
    ]
    
    for query in test_queries:
        print(f"📝 Query: '{query}'")
        result = query_agent.query(query)
        
        if result["success"]:
            print(f"✅ Success - Type: {result.get('type', 'unknown')}")
            if result.get("data", {}).get("message"):
                print(f"   Message: {result['data']['message']}")
            if result.get("visualization"):
                print(f"   Suggested visualization: {result['visualization']}")
        else:
            print(f"❌ Failed: {result.get('error', 'Unknown error')}")
        print()
    
    # 3. Test Mermaid diagram generation
    print("3. Testing Mermaid diagram generation...\n")
    
    # Generate network topology diagram
    nodes = list(store.network_data["nodes"].values())
    connections = store.network_data["connections"]
    
    mermaid_diagram = mermaid_gen.generate_network_graph(nodes, connections, "Test Network Topology")
    print("📊 Generated Network Topology Diagram:")
    print(mermaid_diagram[:500] + "..." if len(mermaid_diagram) > 500 else mermaid_diagram)
    print()
    
    # Generate protocol distribution pie chart
    proto_data = {proto: info["count"] for proto, info in store.network_data["protocols"].items()}
    pie_diagram = mermaid_gen.generate_pie_chart(proto_data, "Protocol Distribution")
    print("📊 Generated Protocol Distribution Chart:")
    print(pie_diagram)
    print()
    
    # 4. Test query result visualization
    print("4. Testing query result to Mermaid conversion...\n")
    
    result = query_agent.query("what is the network topology")
    if result["success"]:
        diagram = mermaid_gen.generate_from_query_result(result)
        if diagram:
            print("✅ Successfully generated diagram from query result")
            print(f"   Diagram length: {len(diagram)} characters")
        else:
            print("❌ Failed to generate diagram from query result")
    
    print("\n✨ All tests completed!")
    print("\n📌 Summary:")
    summary = store.get_summary()
    for key, value in summary.items():
        if isinstance(value, dict):
            print(f"   {key}:")
            for k, v in value.items():
                print(f"      {k}: {v}")
        else:
            print(f"   {key}: {value}")

if __name__ == "__main__":
    test_system()