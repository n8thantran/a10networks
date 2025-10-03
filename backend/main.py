"""
FastAPI server for network packet analysis with multi-agent threat detection
"""
import asyncio
import json
import logging
from typing import AsyncGenerator, Dict, Any, List
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import uvicorn
from datetime import datetime, timezone
import uuid

from agents.analysis.criteria_graph import CriteriaSelectionWorkflow
from agents.analysis.threat_agent_graph import ThreatAnalysisWorkflow
from scrapers.packet_capture import PacketCapture
from models.packet import Packet, AnalysisResult

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="NetSentinel Network Security Monitor")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize components
criteria_workflow = CriteriaSelectionWorkflow()
threat_workflow = ThreatAnalysisWorkflow()
packet_capture = PacketCapture()

# In-memory storage for session data
packet_history = []
criteria_history = []

# Active packet capture sessions
capture_sessions: Dict[str, asyncio.Task] = {}

class CriteriaRequest(BaseModel):
    description: str
    user_id: str = "default"

class CaptureRequest(BaseModel):
    filter_string: str
    interface: str = "any"
    session_id: str = None

class PacketData(BaseModel):
    raw_data: Dict[str, Any]
    timestamp: str
    session_id: str

@app.post("/api/criteria/generate")
async def generate_criteria(request: CriteriaRequest):
    """Generate Scapy filter criteria from natural language description"""
    try:
        result = await criteria_workflow.process_description(
            request.description,
            request.user_id
        )
        
        # Store the criteria in memory
        criteria_history.append({
            "description": request.description,
            "filter_string": result["scapy_filter"],
            "user_id": request.user_id,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        
        return {
            "success": True,
            "filter_string": result["scapy_filter"],
            "validation": result["validation_result"],
            "criteria_id": result.get("criteria_id")
        }
    except Exception as e:
        logger.error(f"Criteria generation failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/capture/start")
async def start_capture(request: CaptureRequest, background_tasks: BackgroundTasks):
    """Start packet capture with specified filter"""
    session_id = request.session_id or str(uuid.uuid4())
    
    if session_id in capture_sessions:
        return {"error": "Session already exists", "session_id": session_id}
    
    # Create capture task
    capture_task = asyncio.create_task(
        packet_capture.start_capture(
            filter_string=request.filter_string,
            interface=request.interface,
            session_id=session_id,
            callback=lambda pkt: asyncio.create_task(process_packet(pkt, session_id))
        )
    )
    
    capture_sessions[session_id] = capture_task
    
    return {
        "success": True,
        "session_id": session_id,
        "status": "capturing"
    }

@app.post("/api/capture/stop/{session_id}")
async def stop_capture(session_id: str):
    """Stop packet capture session"""
    if session_id not in capture_sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    
    capture_task = capture_sessions[session_id]
    capture_task.cancel()
    
    try:
        await capture_task
    except asyncio.CancelledError:
        pass
    
    del capture_sessions[session_id]
    
    return {"success": True, "session_id": session_id, "status": "stopped"}

async def process_packet(packet_data: Dict[str, Any], session_id: str):
    """Process captured packet through threat analysis workflow"""
    try:
        # Create packet object
        packet = Packet(
            raw_data=packet_data,
            timestamp=datetime.now(timezone.utc).isoformat(),
            session_id=session_id
        )
        
        # Run threat analysis
        analysis_results = await threat_workflow.analyze_packet(packet)
        
        # Store results in memory
        packet_history.append({
            "packet": packet.model_dump(),
            "analysis": analysis_results,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        
        # Send to SSE stream if connected
        await broadcast_analysis(session_id, analysis_results)
        
    except Exception as e:
        logger.error(f"Packet processing error: {str(e)}")

@app.get("/api/stream/{session_id}")
async def stream_analysis(session_id: str):
    """Server-Sent Events stream for real-time packet analysis"""
    async def event_generator() -> AsyncGenerator[str, None]:
        queue = asyncio.Queue()
        
        # Register this queue for the session
        if session_id not in stream_queues:
            stream_queues[session_id] = []
        stream_queues[session_id].append(queue)
        
        try:
            while True:
                # Wait for new analysis results
                data = await queue.get()
                
                # Format as SSE
                event = f"data: {json.dumps(data)}\n\n"
                yield event
                
        except asyncio.CancelledError:
            # Clean up on disconnect
            stream_queues[session_id].remove(queue)
            if not stream_queues[session_id]:
                del stream_queues[session_id]
            raise
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        }
    )

# Store for SSE stream queues
stream_queues: Dict[str, List[asyncio.Queue]] = {}

async def broadcast_analysis(session_id: str, analysis: AnalysisResult):
    """Broadcast analysis results to all connected SSE streams"""
    if session_id in stream_queues:
        data = {
            "timestamp": analysis.timestamp,
            "threat_level": analysis.threat_level,
            "threats": analysis.threats,
            "packet_summary": analysis.packet_summary
        }
        
        for queue in stream_queues[session_id]:
            await queue.put(data)

@app.post("/api/analyze/packet")
async def analyze_single_packet(packet_data: PacketData):
    """Analyze a single packet"""
    try:
        packet = Packet(
            raw_data=packet_data.raw_data,
            timestamp=packet_data.timestamp,
            session_id=packet_data.session_id
        )
        
        analysis_results = await threat_workflow.analyze_packet(packet)
        
        # Store in memory
        packet_history.append({
            "packet": packet.model_dump(),
            "analysis": analysis_results,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        
        return {
            "success": True,
            "analysis": analysis_results.model_dump()
        }
    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/search/packets")
async def search_packets(query: str, limit: int = 10):
    """Search packet history (simple text search)"""
    try:
        # Simple text search in packet history
        results = []
        query_lower = query.lower()
        
        for entry in packet_history[-100:]:  # Search last 100 packets
            packet_str = json.dumps(entry).lower()
            if query_lower in packet_str:
                results.append(entry)
                if len(results) >= limit:
                    break
        
        return {
            "success": True,
            "results": results,
            "total_found": len(results)
        }
    except Exception as e:
        logger.error(f"Search failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "active_sessions": len(capture_sessions),
        "stream_connections": sum(len(queues) for queues in stream_queues.values())
    }

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )