# NetSentinel Network Security Monitor - Backend

Real-time network packet analysis with AI-powered threat detection using multi-agent workflows.

## Features

- **Network Packet Capture**: Real-time packet sniffing using Scapy with Linux privilege escalation
- **Natural Language Filter Generation**: Convert descriptions to BPF filters using LLM agents
- **Parallel Threat Analysis**: Multiple specialized agents detect XSS, SQL injection, DoS, and data leaks
- **Server-Sent Events (SSE)**: Real-time streaming of analysis results
- **RESTful API**: FastAPI-based backend with automatic documentation

## Architecture

### Multi-Agent Workflows (NetSentinel Core)

1. **Criteria Selection Workflow** (Cyclic Graph)
   - Natural language to BPF filter conversion
   - QA validation loop to prevent hallucinations
   - Iterative refinement until correct

2. **Threat Analysis Workflow** (DAG Pattern)
   - Parallel execution of specialized agents:
     - XSS Detector
     - SQL Injection Detector
     - DoS Attack Detector
     - Data Leak Detector
     - Anomaly Detector
   - Results aggregation with threat level assessment

## Installation

### Prerequisites
- Python 3.8+
- Linux system (for packet capture)
- Root/sudo access (for network interface access)
- OpenAI API key for GPT-4o-mini access

### Setup

1. Clone the repository:
```bash
cd backend
```

2. Create and activate virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Configure environment:
```bash
cp .env.example .env
# Edit .env with your API keys
```

5. Run the server:
```bash
# With root privileges (recommended for packet capture)
sudo ./run.sh

# Or directly with Python
sudo python main.py
```

## API Endpoints

### Criteria Generation
- `POST /api/criteria/generate` - Generate Scapy filter from natural language

### Packet Capture
- `POST /api/capture/start` - Start packet capture session
- `POST /api/capture/stop/{session_id}` - Stop capture session

### Analysis
- `POST /api/analyze/packet` - Analyze single packet
- `GET /api/search/packets` - Search packet history

### Real-time Streaming
- `GET /api/stream/{session_id}` - SSE stream for live analysis

### System
- `GET /api/health` - Health check
- `GET /docs` - Interactive API documentation

## Usage Examples

### 1. Generate Filter from Description
```bash
curl -X POST "http://localhost:8000/api/criteria/generate" \
  -H "Content-Type: application/json" \
  -d '{
    "description": "Monitor all web traffic for SQL injection attempts",
    "user_id": "user123"
  }'
```

### 2. Start Packet Capture
```bash
curl -X POST "http://localhost:8000/api/capture/start" \
  -H "Content-Type: application/json" \
  -d '{
    "filter_string": "tcp port 80 or tcp port 443",
    "interface": "eth0"
  }'
```

### 3. Stream Real-time Analysis
```javascript
const eventSource = new EventSource('http://localhost:8000/api/stream/session-id');
eventSource.onmessage = (event) => {
  const analysis = JSON.parse(event.data);
  console.log('Threat Level:', analysis.threat_level);
  console.log('Threats:', analysis.threats);
};
```

## Security Considerations

- Requires root/sudo for packet capture on network interfaces
- API keys should be kept secure in environment variables
- CORS is configured for localhost only by default
- Consider using HTTPS in production environments
- Packet data may contain sensitive information

## Troubleshooting

### Permission Denied for Packet Capture
Run with sudo or as root user:
```bash
sudo python main.py
```

### ImportError for Scapy
Install system dependencies:
```bash
sudo apt-get install python3-scapy  # Debian/Ubuntu
sudo yum install python3-scapy      # RHEL/CentOS
```

### LLM API Errors
- Verify OPENAI_API_KEY is set correctly in .env
- Check OpenAI API rate limits and quotas
- GPT-4o-mini is optimized for speed and cost-effectiveness

## Development

### Project Structure
```
backend/
├── agents/           # Multi-agent workflows
│   └── analysis/     # Threat detection agents
├── scrapers/         # Packet capture module
├── models/           # Data models
├── main.py           # FastAPI application
└── requirements.txt  # Dependencies
```

### Adding New Threat Detectors
1. Add detection logic to `threat_agent_graph.py`
2. Create new node in the workflow graph
3. Add patterns to threat_patterns database

### Testing
```bash
# Run packet capture test
sudo python scrapers/packet_capture.py

# Test criteria generation
python agents/analysis/criteria_graph.py

# Test threat analysis
python agents/analysis/threat_agent_graph.py
```

## License
MIT