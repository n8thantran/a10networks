"""
Data models for packet and analysis results
"""
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone

class Packet(BaseModel):
    """Network packet data model"""
    raw_data: Dict[str, Any]
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    session_id: str
    packet_id: Optional[str] = None
    
    class Config:
        arbitrary_types_allowed = True

class Threat(BaseModel):
    """Threat detection result"""
    type: str
    severity: str
    description: str
    pattern: Optional[str] = None
    confidence: float = 1.0

class AnalysisResult(BaseModel):
    """Packet analysis result"""
    timestamp: str
    threat_level: str
    threats: List[Threat] = []
    packet_summary: str
    total_threats: int = 0
    analysis_complete: bool = True
    error: Optional[str] = None
    
    def model_dump(self):
        return {
            "timestamp": self.timestamp,
            "threat_level": self.threat_level,
            "threats": [t.model_dump() for t in self.threats],
            "packet_summary": self.packet_summary,
            "total_threats": self.total_threats,
            "analysis_complete": self.analysis_complete,
            "error": self.error
        }