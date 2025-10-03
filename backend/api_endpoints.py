"""
API endpoints for network query and visualization
"""
from fastapi import APIRouter, HTTPException, WebSocket
from pydantic import BaseModel
from typing import Optional, List
import asyncio
from storage.network_store import NetworkDataStore
from storage.attack_reports import AttackReportStorage
from agents.network_query_agent import NetworkQueryAgent
from agents.mermaid_generator import MermaidGenerator
# Remove attack_simulator import as it doesn't exist

router = APIRouter()

# Components will be initialized from main_ws.py
network_store = None
attack_report_storage = None
query_agent = None
mermaid_gen = None

def init_components(store, report_storage, agent, generator):
    """Initialize components from main app"""
    global network_store, attack_report_storage, query_agent, mermaid_gen
    network_store = store
    attack_report_storage = report_storage
    query_agent = agent
    mermaid_gen = generator

class QueryRequest(BaseModel):
    query: str

class QueryResponse(BaseModel):
    success: bool
    query: str
    type: Optional[str] = None
    data: Optional[dict] = None
    visualization: Optional[str] = None
    mermaidDiagram: Optional[str] = None
    error: Optional[str] = None

@router.post("/api/query", response_model=QueryResponse)
async def process_query(request: QueryRequest):
    """Process natural language network query"""
    import logging
    logger = logging.getLogger(__name__)
    
    try:
        logger.info(f"Processing query: '{request.query}'")
        
        # Check if components are initialized
        if query_agent is None:
            logger.error("Query agent not initialized!")
            return QueryResponse(
                success=False,
                query=request.query,
                error="Query agent not initialized. Please restart the server."
            )
        
        # Process the query
        result = query_agent.query(request.query)
        
        logger.info(f"Query result type: {result.get('type')}")
        logger.info(f"Query success: {result.get('success')}")
        
        # Generate mermaid diagram if applicable
        mermaid_diagram = None
        if result.get("success") and result.get("visualization"):
            mermaid_diagram = mermaid_gen.generate_from_query_result(result)
        
        return QueryResponse(
            success=result.get("success", False),
            query=request.query,
            type=result.get("type"),
            data=result.get("data"),
            visualization=result.get("visualization"),
            mermaidDiagram=mermaid_diagram,
            error=result.get("error")
        )
    
    except Exception as e:
        logger.error(f"Error processing query: {e}")
        return QueryResponse(
            success=False,
            query=request.query,
            error=str(e)
        )

@router.get("/api/network/summary")
async def get_network_summary():
    """Get network summary statistics"""
    try:
        summary = network_store.get_summary()
        return {
            "success": True,
            "data": summary
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/api/network/nodes")
async def get_network_nodes():
    """Get all network nodes"""
    try:
        nodes = network_store.query_nodes()
        return {
            "success": True,
            "nodes": nodes,
            "count": len(nodes)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/api/network/connections")
async def get_network_connections():
    """Get all network connections"""
    try:
        connections = network_store.network_data["connections"]
        return {
            "success": True,
            "connections": connections,
            "count": len(connections)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/api/network/top-talkers")
async def get_top_talkers(limit: int = 10):
    """Get top network talkers"""
    try:
        top_talkers = network_store.get_top_talkers(limit)
        return {
            "success": True,
            "top_talkers": top_talkers,
            "limit": limit
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/api/network/anomalies")
async def get_anomalies(hours: int = 24):
    """Get recent anomalies"""
    try:
        anomalies = network_store.get_recent_anomalies(hours)
        return {
            "success": True,
            "anomalies": anomalies,
            "time_range": f"{hours} hours",
            "count": len(anomalies)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/api/network/clear-old-data")
async def clear_old_data(days: int = 7):
    """Clear data older than specified days"""
    try:
        network_store.clear_old_data(days)
        return {
            "success": True,
            "message": f"Cleared data older than {days} days"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class DDoSRequest(BaseModel):
    target_ip: str = "10.0.0.1"
    target_port: Optional[int] = None
    wave_size: int = 50
    duration: int = 10  # seconds
    mixed_attack: bool = True

@router.post("/api/attack/ddos")
async def simulate_ddos(request: DDoSRequest):
    """Simulate a DDoS attack for demonstration"""
    try:
        # Generate attack packets
        packets = attack_sim.generate_ddos_wave(
            target_ip=request.target_ip,
            target_port=request.target_port,
            wave_size=request.wave_size,
            mixed_attack=request.mixed_attack
        )
        
        # Store packets in network store
        for packet in packets:
            network_store.add_connection(
                src_ip=packet["src_ip"],
                dst_ip=packet["dst_ip"],
                protocol=packet["protocol"].lower(),
                port=packet["dst_port"],
                bytes=packet["size"],
                threat_level=packet["threat_level"]
            )
            
            # Add as anomaly
            if packet.get("threats"):
                for threat in packet["threats"]:
                    network_store.add_anomaly(
                        anomaly_type=threat["type"],
                        description=threat["description"],
                        severity=threat["severity"],
                        source=packet["src_ip"],
                        target=packet["dst_ip"]
                    )
        
        # Generate statistics
        stats = attack_sim.generate_attack_statistics(packets)
        
        # Save the data
        network_store.save()
        
        return {
            "success": True,
            "message": f"DDoS attack simulation launched against {request.target_ip}",
            "packets_generated": len(packets),
            "statistics": stats,
            "packets": packets[:10]  # Return first 10 packets as sample
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/api/test-mermaid")
async def test_mermaid():
    """Test endpoint for Mermaid diagram generation"""
    try:
        # Create test data
        test_nodes = [
            {"id": "n1", "ip": "192.168.1.1", "hostname": "router", "type": "router"},
            {"id": "n2", "ip": "192.168.1.100", "hostname": "client", "type": "host"},
            {"id": "n3", "ip": "192.168.1.200", "hostname": "server", "type": "server"}
        ]
        
        test_connections = [
            {"source": "n2", "target": "n3", "protocol": "tcp", "port": 443},
            {"source": "n2", "target": "n1", "protocol": "udp", "port": 53}
        ]
        
        # Generate diagram
        diagram = mermaid_gen.generate_network_graph(test_nodes, test_connections, "Test Network")
        
        return {
            "success": True,
            "mermaidDiagram": diagram,
            "message": "Test diagram generated successfully"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))